#Goes through every VM, copies the name, renames the VM in Hyper-V, renames the disk, and then reboots
$VMs = get-vm | where {$_.State -ne "Off"}
$Username = ""
$Password = "" | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username,$password)

$VMs | %{
    [String]$Disk = $_.HardDrives.path
    [String]$Name = Invoke-Command -VMName $_.name -ScriptBlock {hostname}  -Credential $credential

    $Splits = $Disk.Split('.').split('\')[0..2]
    $NewDisk = $Splits[0]+'\'+$Splits[1]+'\'+$Splits[2]+'\'+$Name+'.vhdx'
    
    if($Name -ne $_.Name -or $Disk -ne $NewDisk){
        stop-VM $_
        Rename-VM -vm $_ -NewName $Name

        rename-item $Disk -NewName $NewDisk
        Set-VMHardDiskDrive -VMName $Name -Path $NewDisk -ControllerType SCSI
        Start-VM $_
    }
    else{ Write-Host -ForegroundColor Red "VM: $Name VM and disk's already named correctly." }
}
