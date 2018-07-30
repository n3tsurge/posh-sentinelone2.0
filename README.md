# posh-sentinelone2.0
PowerShell Module for Managing a SentinelOne Installation - Central Park (2.6) or Higher

## Usage Example

```
$s1 = [S1API]::new("https://myinstance.sentinelone.net", "MYAPIKEY")
$s1.Proxy = ""
$s1.ProxyUseDefaultCredentials = $true

$agent = $s1.GetAgent('DESKTOP-A10921')
$agent.DisconnectNetwork()
```
