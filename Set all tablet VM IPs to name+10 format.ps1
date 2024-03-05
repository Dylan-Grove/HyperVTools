#This will select all VMs that have "TB" in the name. Extract their name, isolate the last 2 digits, add 10 to that, then set the IP address of the VM to that.
#Make sure the subnet provided is in format number.number.number like 10.1.31
#P31TB01 -> 01 -> 11 -> 10.1.31.11

try {

    # Check if subnet is in the format of "number.number.number"
    if ($subnet -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        throw "Invalid subnet format. Subnet should be in the format of number.number.number."
    }

    # Check if each number in the subnet is less than or equal to 255
    $subnetNumbers = $subnet -split '\.'
    foreach ($number in $subnetNumbers) {
        if (![int]::TryParse($number, [ref]$null) -or [int]$number -gt 255) {
            throw "Invalid subnet. Each number in the subnet should not exceed 255."
        }
    }

    # If the script reaches this point, the subnet is valid
    Write-Host "Subnet is valid."
}
catch {
    Write-Host "Error: $_"
    break
}




$VMs = get-vm | where {$_.name -like "*tb*"}
$Username = ""
$Password = "" | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username,$password)

$VMs | %{

    invoke-Command -VMName $_.name -Credential $credential -ScriptBlock {
        $computerName = $env:COMPUTERNAME  # Retrieve the computer name

        # Extract the number from the computer name
        $number = $computerName -replace '.*(\d{2})$', '$1'
        if ($number -match '\d+') {
            $ipSuffix = [int]$number + 10
            $ipAddress = $subnet+"."+$ipSuffix
    
            # Set the IP address
            $adapter = Get-NetAdapter | Where-Object {$_.Name -like "GbE1"}
            if ($adapter) {
                $currentIPConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex
                $currentIPAddress = $currentIPConfig.IPv4Address
                $currentIPAddressToDelete = $currentIPAddress | Where-Object {$_.IPAddress -ne $ipAddress}
        
                if ($currentIPAddressToDelete) {
                    $currentIPAddressToDelete | ForEach-Object {
                        $params = @{
                            InterfaceIndex = $adapter.InterfaceIndex
                            IPAddress = $_.IPAddress
                            PrefixLength = $_.PrefixLength
                        }
                        Remove-NetIPAddress @params -Confirm:$False
                        Write-Host "Old IP address removed: $($_.IPAddress)"
                    }
                }

                $params = @{
                    InterfaceIndex = $adapter.InterfaceIndex
                    IPAddress = $ipAddress
                    PrefixLength = 24
                }
                New-NetIPAddress @params
                Write-Host "IP address updated successfully. New IP: $ipAddress"
            } else {
                Write-Host "Adapter not found for computer $computerName."
            }
        } else {
            Write-Host "Invalid computer name format. Expected format: P31TBxx"
        }
    }  
}