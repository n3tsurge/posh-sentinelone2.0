THIS REPOSITORY IS NO LONGER UNDER ACTIVE DEVELOPMENT

# posh-sentinelone2.0
PowerShell Module for Managing a SentinelOne Installation - Central Park (2.6) or Higher

## Usage Example

### Code
```
$s1 = [S1API]::new("https://myinstance.sentinelone.net", "MYAPIKEY")
$s1.Proxy = "http://192.168.1.1:8080"
$s1.ProxyUseDefaultCredentials = $true

$agent = $s1.GetAgent('DESKTOP-A10921')
$agent.ListApplications() | ft
```
### Response
```
[7/30/2018 4:08:28 PM][USR:1][zerosec@securitas ~]
$ F:\Repositories\posh-sentinelone-2.0\Posh-SentinelOne.ps1

installedDate               name                                                           publisher               size version       
-------------               ----                                                           ---------               ---- -------       
2018-07-30T00:00:00Z        Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161 Microsoft Corporation  10440 9.0.30729.6161
2018-07-30T00:00:00Z        VMware Tools                                                   VMware, Inc.          105784 10.1.6.5214329
2018-07-30T00:00:00Z        Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161 Microsoft Corporation  13532 9.0.30729.6161
2018-07-30T00:00:00Z        Sentinel Agent                                                 SentinelOne                0 2.6.3.5948    
2018-07-30T19:11:41.007000Z Mozilla Maintenance Service                                    Mozilla                  278 61.0.1        
2018-07-30T19:11:40.335000Z Mozilla Firefox 61.0.1 (x64 en-US)                             Mozilla               147929 61.0.1      
```
