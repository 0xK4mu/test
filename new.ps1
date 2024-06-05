# Modify registry keys
$regPath = "HKCU:\Software\EDRTestKey"
New-Item -Path $regPath
Set-ItemProperty -Path $regPath -Name "TestValue" -Value "EDRTest"
Remove-Item -Path $regPath -Recurse

# Start and stop a service
$serviceName = "wuauserv" # Windows Update service
Start-Service -Name $serviceName
Stop-Service -Name $serviceName

# Execute a suspicious command
Invoke-Expression -Command "ping 127.0.0.1 -n 1; whoami; tasklist"
