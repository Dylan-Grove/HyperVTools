$SourceFiles = Get-ChildItem C:\Scripts -Recurse -File
$VMs = Get-VM | Where {$_.Name -like "*TB*"}

$VMs | $SourceFiles | % { Copy-VMFile -SourcePath $_.FullName -DestinationPath $_.FullName -CreateFullPath -FileSource Host }