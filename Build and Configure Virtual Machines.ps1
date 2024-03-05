#This script is intended to be run on a brand new hyper-v server. It will build and configure all the servers, tablets, and KDS vms.
#Variables:
#SiteNumber should be a either 2 digits for CBH (example.  37 for Manning) or 4 digits for BQT (example. 2004 for Mahogany)

#region Required Variables
<#
$GoldImagePath = "D:\Hyper-V\Images\Image.vhdx"
$VirtualDisksPath = "D:\Hyper-V\Virtual Disks"
$Timezone = "Mountain Standard Time"
$VirtualSwitchName = ""
$VirtualSwitchNIC = "NIC1"
$SiteIP = '40'
$SiteNumber = '40'
$DefaultGatewayIP = '126'
$DNS1IP = '126'
$DNS2IP = '1.1.1.1'
$TabletCount = 20
$Brand = 'Brewhouse'
$CreateKDSVMs = "True"
$CreateTabletVMs = "True"
$CreateKDSServerVM = "True"
$CreateCAPSServerVM = "True"
$CreateSTSServerVM = "True"
$CreateUpBarKDSVMs = "True"
$CreateDownBarKDSVMs = "True"
#>
# Enter KDS Names here
# The order matters, the position in this list dictates the IP address the device will be given. EXPO = .101, Pizza = .105


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
    )
if ($CreateUpBarKDSVMs -eq "True"){
        $KDSNames += @(
            "WSKDSDP${SiteNumber}UBAREX",
            "WSKDSDP${SiteNumber}UBAR"
        )
}
if ($CreateDownBarKDSVMs -eq "True"){
        $KDSNames += @(
            "WSKDSDP${SiteNumber}DBAREX",
            "WSKDSDP${SiteNumber}DBAR"
        )
}


# Networks
If($Brand -eq "Brewhouse"){$SiteSubnet = "10.1.$SiteIP"}
Elseif($Brand -eq "Banquet"){$SiteSubnet = "10.3.$SiteIP"}
$DefaultGateway = $SiteSubnet+"."+$DefaultGatewayIP
$DNS1 = $SiteSubnet + "." + $DNS1IP
$DNS2 = $DNS2IP

# Credentials
$Username = "ENTER USERNAME HERE"
$Password = "ENTER PASSWORD HERE" | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username,$password)

#endregion


#region Functions

# Log file path
$Date = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFileFolder = "C:\CBH-IT\Scripts\Logs\"
$LogFile = $LogFileFolder + "CreateAndConfigureVirtualMachines-$Date.txt"
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
        [ValidateScript({Test-Path $VirtualDisksPath})]
        [String]$VirtualDisksPath,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $VirtualDisksPath})]
        [String]$GoldImagePath,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $MemoryStartupBytes,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Int32]$CPUCores,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Get-VMSwitch -Name $VirtualSwitchName})]
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
        New-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name DefaultUserName -Value "ENTER USERNAME HERE" 2>&1 | out-null
        New-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name DefaultPassword -Value 'ENTER PASSWORD HERE' 2>&1 | out-null
        Set-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name DefaultUserName -Value "ENTER USERNAME HERE" 2>&1 | out-null
        Set-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name DefaultPassword -Value 'ENTER PASSWORD HERE' 2>&1 | out-null
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
#endregion Functions


#region Start script and confirm variables are correct

Write-Log "Confirming all user-entered variables are valid..." -Severity INFO

$SiteIP = [Int32]$SiteIP
$SiteNumber = [Int32]$SiteNumber
$TabletCount = [Int32]$TabletCount
Try {
    If (!(Test-Path -Path $GoldImagePath)) {Throw "GoldImagePath $GoldImagePath was not found. Please download the file to this folder on the Hyper-V"}
    If (!(Test-Path -Path $VirtualDisksPath)) {Throw "VirtualDisksPath $VirtualDisksPath was not found. Please ensure the correct path is entered and the folder exists on the server."}
    If (!(Get-NetAdapter -Name $VirtualSwitchNIC -ErrorAction SilentlyContinue)) {Throw "VirtualSwitchNIC $VirtualSwitchNIC not found on server."}
    If ($SiteIP -is [INT32] -and $SiteIP -gt 254 -or $SiteIP -lt 1) {Throw "SiteIP $SiteIP is in the wrong format, ensure it's only 2-3 digits long and an integer. example: 40 not 10.1.40.0"}
    If (($SiteNumber -is [INT32] -and ($SiteNumber | Measure-Object -Character).Characters -gt 4 -or ($SiteNumber | Measure-Object -Character).Characters -lt 1)) {Throw "SiteNumber $SiteNumber is in the wrong format, ensure it's only 2 or 4 digits long and an integer."}
    If (!($TabletCount -is [INT32])) {Throw "TabletCount $TabletCount is the wrong format, ensure it's an integer."}
    If ((Get-VMSwitch $VirtualSwitchName | measure-object).count -ge 2){Throw "Multiple virtual switches with the same name found. Remove one and re-run the script."}
} Catch {
    Write-Host "Variable confirmation failed. Refer to the log for more information - $LogFile" -ForegroundColor Red
    Write-Log "Variable confirmation failed. Refer to the log for more information - $LogFile" -Severity ERROR
    Write-Log $_ -Severity ERROR
    Throw $_
}
#endregion


#region Create Virtual Switch
Write-Log "Checking if virtual switch exists already." -Severity INFO
$existingSwitch = Get-VMSwitch -Name $VirtualSwitchName -ErrorAction SilentlyContinue

if ($existingSwitch -eq $null) {
    if ($netAdapter = Get-NetAdapter -Name $VirtualSwitchNIC) {
        Write-Log "Virtual switch '$VirtualSwitchName' does not exist yet, creating virtual switch." -Severity INFO
        Write-Host "Virtual switch '$VirtualSwitchName' does not exist yet, creating virtual switch."
        New-VMSwitch -Name $VirtualSwitchName -NetAdapterName $netAdapter.Name
        } 
    else {
        Write-Host "Network adapter '$VirtualSwitchNIC' not found." -ForegroundColor Red
        Write-Log "Network adapter '$VirtualSwitchNIC' not found." -Severity ERROR
    }
}
Else {
    Write-Host "Virtual Switch '$VirtualSwitchName' already exists. Skipping Creation." -ForegroundColor Yellow
    Write-Log "Virtual Switch '$VirtualSwitchName' already exists. Skipping Creation." -Severity WARN
}
#endregion 


#region Create Virtual Machines

# Create Servers
if ($CreateCAPSServerVM -eq "True"){
    CreateVirtualMachine -Name "P${SiteNumber}CAPS" -MemoryStartupBytes 8GB -CPUCores 4 -VirtualDisksPath $VirtualDisksPath -GoldImagePath $GoldImagePath -VirtualSwitchName $VirtualSwitchName
}
Else{
    Write-Log "Option to build CAPS VM was set to False. Skipping VM/Disk creation." -Severity WARN
}
if ($CreateKDSServerVM -eq "True"){
    CreateVirtualMachine -Name "P${SiteNumber}KDS" -MemoryStartupBytes 8GB -CPUCores 4 -VirtualDisksPath $VirtualDisksPath -GoldImagePath $GoldImagePath -VirtualSwitchName $VirtualSwitchName
}
Else{
    Write-Log "Option to build KDS VM was set to False. Skipping VM/Disk creation." -Severity WARN
}
if ($CreateSTSServerVM -eq "True"){
    CreateVirtualMachine -Name "P${SiteNumber}STS" -MemoryStartupBytes 8GB -CPUCores 4 -VirtualDisksPath $VirtualDisksPath -GoldImagePath $GoldImagePath -VirtualSwitchName $VirtualSwitchName
}
Else{
    Write-Log "Option to build STS VM was set to False. Skipping VM/Disk creation." -Severity WARN
}


# Create Tablets
if ($CreateTabletVMs -eq "True"){
    $TabletCount = $TabletCount -as [int]
    1..$TabletCount | ForEach-Object {
        $Index = $_
        if ($_ -gt 9) { $Name = "P${SiteNumber}TB${_}" } 
        else { $Name = "P${SiteNumber}TB0${_}" }
        CreateVirtualMachine  -MemoryStartupBytes 4GB -CPUCores 2 -Name $Name -VirtualDisksPath $VirtualDisksPath -GoldImagePath $GoldImagePath -VirtualSwitchName $VirtualSwitchName
    }
}
Else{
    Write-Log "Option to build tablet VMs was set to False. Skipping VM/Disk creation." -Severity WARN
}


# Create KDS
if ($CreateKDSVMs -eq "True"){
    $KDSList = $KDSNames | ForEach-Object -Begin { $ipCounter = 101 } -Process {
    $ip = "$SiteSubnet.$($ipCounter)"
    $ipCounter++
        [PSCustomObject]@{
            Name = $_
            IP = $ip
        }
    }
    $KDSList | % { CreateVirtualMachine -Name $_.Name -MemoryStartupBytes 4GB -CPUCores 2 -VirtualDisksPath $VirtualDisksPath -GoldImagePath $GoldImagePath -VirtualSwitchName $VirtualSwitchName }
}
Else{
    Write-Log "Option to build KDS VMs was set to False. Skipping VM/Disk creation." -Severity WARN
}

#endregion Create Virtual Machines


#region Configure Virtual Machines
Write-Log "Virtual Machine creation completed. Moving on to configuration." -Severity INFO
Write-Log "Attempting to start all virtual machines..." -Severity INFO
Get-VM | Where-Object {$_.Name -like "*P${SiteNumber}*"} | Start-VM
Sleep 60



# Configure Servers
if ($CreateCAPSServerVM -eq "True"){
    ConfigureVirtualMachine -Name "P${SiteNumber}CAPS" -IP ($SiteSubnet + "." + (125))}
Else{
    Write-Log "Option to build CAPS VM was set to False. Skipping configuration." -Severity WARN
}
if ($CreateKDSServerVM -eq "True"){
    ConfigureVirtualMachine -Name "P${SiteNumber}KDS" -IP ($SiteSubnet + "." + (124))}
Else{
    Write-Log "Option to build KDS VM was set to False. Skipping configuration." -Severity WARN
}
if ($CreateSTSServerVM -eq "True"){
    ConfigureVirtualMachine -Name "P${SiteNumber}STS" -IP ($SiteSubnet + "." + (123))
}
Else{
    Write-Log "Option to build STS VM was set to False. Skipping configuration." -Severity WARN
}



# Configure Tablets
1..$TabletCount | % {
    if($_ -gt 9){$Name = "P${SiteNumber}TB$_"}
    else{$Name = "P${SiteNumber}TB0$_"}
    $IP = $SiteSubnet+"."+($_+10)
    If((Get-VM -Name $Name).state -eq "Running"){
        ConfigureVirtualMachine -Name $Name -IP $IP
    }
    Else{
        Write-Log -Severity ERROR "VM $Name is not running. Configuration failed. Ensure VHD was created and there is enough RAM available on the server."
    }
}

# Configure KDS
if ($CreateKDSVMs -eq "True"){
    $KDSList | %{ 
        If((Get-VM -Name $_.Name).state -eq "Running"){
            ConfigureVirtualMachine -Name $_.Name -IP $_.IP 
        }
        Else{
            Write-Log -Severity ERROR "VM $Name is not running. Configuration failed. Ensure VHD was created and there is enough RAM available on the server."
        }
    }
}
Else{
    Write-Log "Option to build KDS VMs was set to False. Skipping configuration." -Severity WARN
}

Write-Log "Script Complete." -Severity INFO
#endregion Configure Virtual Machines