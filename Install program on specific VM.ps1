$Username = ""
$Password = "" | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username,$password)

Try{
    $VM = get-vm | where {$_.Name -eq $VMName}
    If ($VM -eq $Null){ throw }
}
catch {throw "VM Not found, please double-check the name and try again"}

Copy-VMFile -VMName $VM.Name -SourcePath "C:\syncroinstaller.exe" -DestinationPath "C:\Temp\syncroinstaller.exe" -CreateFullPath -FileSource Host -ErrorAction SilentlyContinue
Invoke-Command -VMName $VM.Name -ScriptBlock {start c:\Temp\syncroinstaller.exe} -Credential $credential


