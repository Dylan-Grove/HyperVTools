#Converts a single VM Disk to fixed. Make sure the VM starts properly when the script is done and then delete the old desk from D:\Old Disks
#REQUIRED VARIABLE: VMName
if(Test-Path "D:\Hyper-V\Virtual Disks\$VMName.vhdx"){ $DiskPath = "D:\Hyper-V\Virtual Disks\$VMName.vhdx" }
Elseif(Test-Path "E:\Hyper-V\Virtual Disks\$VMName.vhdx"){ $DiskPath = "E:\Hyper-V\Virtual Disks\$VMName.vhdx" }
Elseif(Test-Path "D:\Hyper-V\Virtual Hard Disks\$VMName.vhdx"){ $DiskPath = "D:\Hyper-V\Virtual Hard Disks\$VMName.vhdx" }
Elseif(Test-Path "E:\Hyper-V\Virtual Disks\$VMName.vhdx"){ $DiskPath = "E:\Hyper-V\Virtual Disks\$VMName.vhdx" }

If(Test-Path $DiskPath){   
    Stop-VM $VMName
    Mkdir "D:\Old Disks" 
    Move-item $DiskPath -destination "D:\Old Disks\$VMName.vhdx"
    Convert-VHD –Path "D:\Old Disks\$VMName.vhdx" –DestinationPath $DiskPath –VHDType Fixed
    Start-VM $VMName
}