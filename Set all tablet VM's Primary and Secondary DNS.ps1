#Grabs all tablets and sets their DNS to the ones you sepcifiy
try {
    $ipAddress1 = [System.Net.IPAddress]::Parse($dns1)
    Write-Host "Valid IP address for DNS 1: $ipAddress1"

    $ipAddress2 = [System.Net.IPAddress]::Parse($dns2)
    Write-Host "Valid IP address for DNS 2: $ipAddress2"

    # Continue with your code here
}
catch {
    if (-not ([System.Net.IPAddress]::TryParse($dns1, [ref]$null))) {
        Write-Host "Invalid IP address for DNS 1: $dns1"
    }

    if (-not ([System.Net.IPAddress]::TryParse($dns2, [ref]$null))) {
        Write-Host "Invalid IP address for DNS 2: $dns2"
    }

    break
}


$VMs = get-vm | where {$_.name -like "*tb*"}
$Username = ""
$Password = "" | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username,$password)

$VMs | %{

    invoke-Command -VMName $_.name -Credential $credential -ScriptBlock {
        $adapterName = "GbE1"  # Replace with the name of your Ethernet adapter
        $dnsServers = $dns1, $dns2

        $adapter = Get-NetAdapter | Where-Object {$_.Name -eq $adapterName}

        if ($adapter) {
            $currentIPConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex
            $currentIPConfig | ForEach-Object {
                $ipConfig = $_
                $dnsServerAddresses = $ipConfig.DNSServer | Select-Object -ExpandProperty ServerAddresses
                if ($dnsServerAddresses -ne $dnsServers) {
                    $dnsServerAddresses = $dnsServers
                    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $dnsServerAddresses
                    Write-Host "DNS servers updated successfully."
                } else {
                    Write-Host "DNS servers are already set to the desired values."
                }
            }
        } else {
            Write-Host "Adapter not found."
        }
    }  
}