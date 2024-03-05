#This will connect to all tablet VMs and add a secondary gateway
#Required variable: secondaryGateway

try {
    $ipAddress = [System.Net.IPAddress]::Parse($secondaryGateway)
    Write-Host "Valid IP address: $ipAddress"
    # Continue with your code here
}
catch {
    Write-Host "Invalid IP address: $secondaryGateway"
    break
}

$VMs = get-vm | where {$_.name -notlike "*tb*"}
$Username = ""
$Password = "" | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username,$password)

$VMs | %{

    invoke-Command -VMName $_.name -Credential $credential -ScriptBlock {
        $adapterName = "GbE1"  # Replace with the name of your Ethernet adapter

        $adapter = Get-NetAdapter | Where-Object {$_.Name -eq $adapterName}

        if ($adapter) {
            $currentIPConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex
            $currentIPConfig | ForEach-Object {
                $ipConfig = $_
                $ipConfig | Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4" -and $_.PrefixOrigin -eq "Manual"} | ForEach-Object {
                    $gatewayAddresses = $_.IPv4DefaultGateway
                    if ($gatewayAddresses -notcontains $secondaryGateway) {
                        $gatewayAddresses += $secondaryGateway
                        $gatewayAddresses = $gatewayAddresses | Select-Object -Unique
                        $cmd = "netsh interface ip add address `"$($adapter.Name)`" gateway=`"$secondaryGateway`" gwmetric=0"
                        Invoke-Expression -Command $cmd
                        Write-Host "Secondary gateway added successfully."
                    } else {
                        Write-Host "Secondary gateway already exists."
                    }
                }
            }
        } else {
            Write-Host "Adapter not found."
        }
    }  
}