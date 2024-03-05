#Gets a list of all disks in a folder and then converts them to fixed. As a precaution, this script will keep the old disks. this may take up additional space and they may need to be deleted after. Note: This requires about 17GB per VM of free disk space on the hyper-v D drive to work.
#REQUIRED VARIABLES: DisksPath AND OldDisksPath
# Logging
$Date = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFileFolder = "D:\Scripts\Logs\"
$LogFile = $LogFileFolder + "ConvertAllTabletsToFixedDisks-$Date.txt"
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


Mkdir $OldDisksPath
Get-ChildItem $Diskspath | %{

    $DiskPath = $_.FullName
    $VMname = ($_.Name).split(".")[0]

    if((Get-VHD -Path $Diskpath).VhdType -eq 'Dynamic'){
        Write-host "$DiskPath is dynamic, setting to fixed..." -ForegroundColor Green
        Write-log "$DiskPath is dynamic, setting to fixed..." -Severity INFO
        Stop-VM $VMname
        if ((get-vm $VMName).state -eq "running") {
            Write-host "$VmName Failed to stop, attempting to force shutdown." -ForegroundColor yellow
            Write-Log "$VmName Failed to stop, attempting to force shutdown." - Severity WARN
            Stop-vm $VMName -force -TurnOff
        }
        if ((get-vm $VMName).state -eq "running") {
            Write-host "$VmName Can't be stopped. Skipping." -ForegroundColor yellow
            Write-Log "$VmName Can't be stopped. Skipping." -Severity ERROR
            continue
        }
        Move-item $DiskPath -destination "D:\Old Disks\$VMName.vhdx"
        Convert-VHD –Path "$OldDisksPath\$VMName.vhdx" –DestinationPath $DiskPath –VHDType Fixed
        Start-VM $VMName
    }
    else {
        Write-host "$DiskPath is already fixed. Skipping." -ForegroundColor yellow
        Write-Log "$DiskPath is already fixed. Skipping." -Severity WARN
    }
}