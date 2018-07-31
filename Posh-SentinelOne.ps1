# API key 
# URL 

class S1API {

    [String]$URL;
    [String]$ApiKey;
    [String]$Token;
    [String]$Proxy=$null;
    [Hashtable]$Headers = @{};
    [Boolean]$ProxyUseDefaultCredentials=$false;
    [HashTable]$RequestParams = @{}

    # Constructor
    S1API ([String]$URL, [String]$APIKey) {
        $this.URL = $URL
        $this.APIKey = $APIKey
        $this.Token = $null
        $this.Proxy = $null

        $this.RequestParams.Add('Uri', $URL)
        $this.RequestParams.Add('Method', 'GET')
        $this.RequestParams.Add('Proxy', $null)
        $this.RequestParams.Add('ProxyUseDefaultCredentials', $false)
        $this.RequestParams.Add('ContentType', 'application/json')
        
        if($this.ApiKey) {
            $this.Headers.Add("Authorization", "ApiToken "+$this.ApiKey)
        }

        $this.RequestParams.Add('Headers', $this.Headers)

    }

    # Performs a user based authentication against the API
    # Definitely don't recommend using this method ever
    # TODO: Make this work...SECURELY
    [void]Login([String]$Username, [String]$Password) {

        $body = @{
            "username"=$Username;
            "password"=$Password;
        }
        
        $results = $this.Post('/web/api/v2.0/users/login', ($body | ConvertTo-Json))

        Write-Host $results

        if($results) {
            $this.Token = $results.token
            $this.Headers.Add("Authorization", "Token "+$this.Token)
        } else {
            raise ValueError("Authentication Failed")
        }

    }

    # Performs an HTTP Get request against the specified endpoint
    [System.Object]Get([String]$Endpoint) {

        $Parameters = @{}
        $this.RequestParams.Uri = $this.URL+$Endpoint
        $this.RequestParams.Method = 'GET'

        if($this.Proxy) {
            $this.RequestParams.Proxy = $this.Proxy
        }

        # If the user wants to use their default proxy credentials, do so
        if($this.Proxy -and $this.ProxyUseDefaultCredentials) {
            $this.RequestParams.ProxyUseDefaultCredentials = $true
        }

        # Clone the Request Parameters so they can be unfurled
        $params = $this.RequestParams

        Write-Host @params
       
        $response = try { Invoke-RestMethod @params } catch { $null }
        
        # If the API wants to paginate, let it 
        if($response.pagination) 
        {
            # Consolidate the returned data in $data so it can be appended in the event
            # of pagination
            $data = $response.data

            While($data.Count -ne $response.pagination.totalItems) {
                $this.RequestParams.Uri += "&cursor="+$response.pagination.nextCursor
                $response = Invoke-RestMethod @params
                $data += $response.data
            }

            $response = $data
        }

        return $response
    }

    # Performs an HTTP Post request against the specified endpoint
    [System.Object]Post([String]$Endpoint, [String]$Body=$null) {

        $this.RequestParams.Uri = $this.URL+$Endpoint
        $this.RequestParams.Method = 'POST'
        $this.RequestParams.Add('Body', $Body)

        if($this.Proxy) {
            $this.RequestParams.Proxy = $this.Proxy
        }

        # If the user wants to use their default proxy credentials, do so
        if($this.Proxy -and $this.ProxyUseDefaultCredentials) {
            $this.RequestParams.ProxyUseDefaultCredentials = $true
        }
        
        # Clone the Request Parameters so they can be unfurled
        $params = $this.RequestParams

        $response = Invoke-RestMethod @params

        return $response.data
    }
    
    # Initial call to get an S1Agent
    # all subsequent actions happen from the Agent object
    [System.Object]GetAgent([String]$AgentName) {
        $agent = [S1Agent]::new($this, $this.Get('/web/api/v2.0/agents?computerName='+$AgentName))
        return $agent
    }

    # Initial call to get multiple S1Agents
    # all subsequent actions ahppen from the Threat object
    [System.Object]GetAgents([String]$AgentName, [Int]$Limit,[Boolean]$Infected) {

        $agents = $this.Get('/web/api/v2.0/agents?limit={0:d0}&infected={1}&computerName__like={2}' -f ($Limit,$Infected,$AgentName))
        
        # If there are no agents, return an empty Hashtable
        if(!$agents) {
            return $null
        }

        # Cast all the returned agents as S1Agent objects
        $agents = $agents | % {
            [S1Agent]::new($this, $_)
        }
        return $agents
    }

    # Initial call to get an S1Threat
    # all subsequent actions ahppen from the Threat object
    [System.Object]GetThreat([String]$id) {
        $threat = [S1Threat]::new($this, $this.Get('/web/api/v2.0/threats?ids='+$id))

        if(!$threat) {
            return $null
        }
        return $threat
    }

    # Initial call to get multiple S1Threats
    # all subsequent actions ahppen from the Threat object
    [System.Object]GetThreats([Boolean]$Resolved) {

        $threats = $this.Get('/web/api/v2.0/threats')

        if(!$threats) {
            return $null
        }

        # Cast all the returned threats as S1Threat objects
        $threats = $threats | % {
            [S1Threat]::new($this, $_)
        }
        return $threats
    }

    [System.Object]GetUsers ([String]$Email) {
           
        $users = $this.Get('/web/api/v2.0/users?query='+$Email)

        if(!$users) {
            return $null
        }

        # Cast all the returned users as S1User objects
        $users = $users | % {
            [S1User]::new($this, $_)
        }
        return $users

    }    
}


<#
The SentinelOne Threat object, gets fed threat data
#>
class S1Threat {

    [System.Object]$Data;
    [S1API]$s1;
    [Hashtable]$PostBody; 

    # Constructor
    S1Threat ([S1API]$s1, [System.Object]$Data) {
        
        # Pull back all the Threat details into the parent object so it can be referend
        # in dot notation
        $Data | Get-Member | % {
            if($_.MemberType -eq "NoteProperty") {
                $this | Add-Member -MemberType $_.MemberType -Name $_.Name -Value ($Data | Select -ExpandProperty $_.Name)
            }  
        }

        $this.s1 = $s1
        $this.PostBody = @{
            "filter" = @{
                "ids" = @($this.id);
                "contentHash"=$this.fileContentHash;
            }
        }
    }

    # Marks the threat as Benign
    # /apidoc/#!/Threats/post_web_api_v2_0_threats_mark_as_benign
    [boolean]MarkAsBenign() {

        try {
            $result = $this.s1.Post('/web/api/v2.0/threats/mark-as-benign', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }

    }


    # Resolve a threat
    # /apidoc/#!/Threats/post_web_api_v2_0_threats_mark_as_resolved
    [boolean]Resolve() {

        try {
            $result = $this.s1.Post('/web/api/v2.0/threats/mark-as-resolved', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }

    }

    # Quarantine a threat
    # /apidoc/#!/Threats/post_web_api_v2_0_threats_mitigate_action
    [boolean]Quarantine() {

        try {
            $result = $this.s1.Post('/web/api/v2.0/threats/mitigate/quarantine', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Un-Quarantines a file
    # /apidoc/#!/Threats/post_web_api_v2_0_threats_mitigate_action
    [boolean]Unquarantine() {

        try {
            $result = $this.s1.Post('/web/api/v2.0/threats/mitigate/un-quarantine', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Rollback Threat
    # /apidoc/#!/Threats/post_web_api_v2_0_threats_mitigate_action
    [boolean]Rollback() {

        try {
            $result = $this.s1.Post('/web/api/v2.0/threats/mitigate/rollback-remediation', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Kill Threat
    # /apidoc/#!/Threats/post_web_api_v2_0_threats_mitigate_action
    [boolean]Kill() {

        try {
            $result = $this.s1.Post('/web/api/v2.0/threats/mitigate/kill', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Remediate Threat
    # /apidoc/#!/Threats/post_web_api_v2_0_threats_mitigate_action
    [boolean]Remediate() {

        try {
            $result = $this.s1.Post('/web/api/v2.0/threats/mitigate/remediate', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Get a list of connects the Threat made
    # /apidoc/#!/Forensics/get_web_api_v2_0_threats_threat_id_forensics_connections
    [System.Object]Connections() {

        try {
            $result = $this.s1.Get("/web/api/v2.0/threats/$($this.id)/forensics/connections")
            return $result
        } catch {
            $_.Exception.Message
            return $null
        }
    }

    # Get Forensics
    # /apidoc/#!/Forensics/get_web_api_v2_0_threats_threat_id_forensics
    [System.Object]Forensics() {

        $result = $this.s1.Get('/web/api/v2.0/threats/{0}/forensics' -f $this.id)

        return $result.result

    }

    # Get Forensics
    # /apidoc/#!/Forensics/get_web_api_v2_0_threats_threat_id_forensics
    [System.Object]ForensicsDetails() {

        $result = $this.s1.Get('/web/api/v2.0/threats/{0}/forensics/details' -f $this.id)

        return $result.result

    }

    # Download the Forensic Data
    # /apidoc/#!/Forensics/get_web_api_v2_0_threats_threat_id_forensics_export_export_format
    [System.Object]ForensicsExport([String]$Format) {
        
        try {
            $result = $this.s1.Get("/web/api/v2.0/threats/$($this.id)/forensics/export/$($Format)")
            return $result
        } catch {
            return $null
        }
    }
}


<# 
The SentinelOne Agent object, gets fed agent data
#>
class S1Agent {

    [System.Object]$Data;
    [S1API]$s1;
    [Hashtable]$PostBody;

    # Constructor
    S1Agent ([S1API]$s1, [System.Object]$Data) {

        # Pull back all the Agent details into the parent object so it can be referenced
        # in dot notation
        $Data | Get-Member | % {
            if($_.MemberType -eq "NoteProperty") {
                $this | Add-Member -MemberType $_.MemberType -Name $_.Name -Value ($Data | Select -ExpandProperty $_.Name)
            }
        }
        $this.s1 = $s1
        $this.PostBody = @{
            "filter" = @{
                "ids" = @($this.id)
            }
        }
    }

    # Disconnects the Agent from the network
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_disconnect
    # Method: POST
    [boolean]DisconnectNetwork() {

        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/disconnect', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Connects the Agent to the network
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_connect
    # Method: POST
    [boolean]ConnectNetwork() {

        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/connect', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Initiates a Full Disk Scan
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_initiate_scan
    # Method: POST
    [boolean]InitiateScan() {
       
        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/initiate-scan', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Initiates a Full Disk Scan
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_abort_scan
    # Method: POST
    [boolean]AbortScan() {
        
        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/abort-scan', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Lists all the processes on the Agent
    # /apidoc/#!/Agents/get_web_api_v2_0_agents_processes
    # Method: GET
    [System.Object]ListProcesses() {
        
        try {
            $result = $this.s1.Get('/web/api/v2.0/agents/processes?ids='+$this.id)
            return $result
        } catch {
            $_.Exception.Message
            return $null
        }
    }

    # Lists all the applications on the Agent
    # /apidoc/#!/Agents/get_web_api_v2_0_agents_applications
    # Method: GET
    [System.Object]ListApplications() {
        
        try {
            $result = $this.s1.Get('/web/api/v2.0/agents/applications?ids='+$this.id)
            return $result
        } catch {
            $_.Exception.Message
            return $null
        }
    }

    # Get the Passphrase for the Agent
    # /apidoc/#!/Agents/get_web_api_v2_0_agents_passphrases
    # Method: GET
    [System.Object]Passphrase() {
        
        try {
            $result = $this.s1.Get('/web/api/v2.0/agents/passphrases?ids='+$this.id)
            return $result
        } catch {
            $_.Exception.Message
            return $null
        }
    }

    # Send a Message to the Agent
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_broadcast
    # Method: POST
    [boolean]SendMessage($message) {

        # Copy the default Post Body and add the data and message elements
        $body = $this.PostBody
        $body.Add("data", @{})
        $body.data.Add("message", $message)
        
        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/broadcast?ids='+$this.id, ($body | ConvertTo-Json))
            return $result
        } catch {
            $_.Exception.Message
            return $null
        }
    }

    # Approve an Uninstall Request
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_approve_uninstall
    # Method: POST
    [boolean]ApproveUninstall() {
        
        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/approve-uninstall', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Reject an Uninstall Request
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_reject_uninstall
    # Method: POST
    [boolean]RejectUninstall() {
        
        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/reject-uninstall', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Decommission Agent
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_decommision
    # Method: POST
    [boolean]Decommission() {
        
        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/decommision', ($this.PostBody | ConvertTo-Json))
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

}

<#
The SentinelOne User Object, gets fed User data
#>
class S1User {
    
    [System.Object]$Data;
    [S1API]$s1;
    [Hashtable]$PostBody;

    S1User ([S1API]$s1, [System.Object]$Data) {

        # Pull back all the Agent details into the parent object so it can be referenced
        # in dot notation
        $Data | Get-Member | % {
            if($_.MemberType -eq "NoteProperty") {
                $this | Add-Member -MemberType $_.MemberType -Name $_.Name -Value ($Data | Select -ExpandProperty $_.Name)
            }
        }
        $this.s1 = $s1
        $this.PostBody = @{
            "filter" = @{
                "ids" = @($this.id)
            }
        }
    }

    # Enable Two-Factor Authentication
    # /apidoc/#!/Users/post_web_api_v2_0_users_2fa_enable
    [boolean]Enable2FA () {

        try { 
            $results = $this.s1.Post('/web/api/v2.0/users/2fa/enable', ($this.PostBody | ConvertTo-Json)) 
        } catch {
            return $false
        }

        return $true
    }

    # Disable Two-Factor Authentication
    # /apidoc/#!/Users/post_web_api_v2_0_users_2fa_disable
    [boolean]Disable2FA () {

        try { 
            $results = $this.s1.Post('/web/api/v2.0/users/2fa/disable', ($this.PostBody | ConvertTo-Json)) 
        } catch {
            return $false
        }

        return $true
    }

    # Generates an API token for the user
    # /apidoc/#!/Users/post_web_api_v2_0_users_generate_api_token
    [System.Object]GenerateAPIToken () {

        $result = try { $this.s1.Post('/web/api/v2.0/users/generate-api-token', ($this.PostBody | ConvertTo-Json)) } catch { $null }
        
        if(!$result) {
            return $null
        }

        return $result
    }

    # Revokes an API token for the user
    # /apidoc/#!/Users/post_web_api_v2_0_users_revoke_api_token
    [System.Object]RevokeAPIToken () {

        $result = try { $this.s1.Post('/web/api/v2.0/users/revoke-api-token', ($this.PostBody | ConvertTo-Json)) } catch { $null }
        
        if(!$result) {
            return $null
        }

        return $result
    }
}

<# START CMDLETS #>

<#
#>
function Get-S1Agent () {
    [CmdletBinding()]
    Param(
        [Parameter()][String]$AgentName
    )

    return $s1.GetAgent($AgentName)
}

<#
Cmdlet for iterating and pulling a large number of Agents
Preferable to use the Cmdlets over the direct $s1.GetAgent call, it requires
the user to put in every parameter, the Cmdlet these parameters are optional
TODO: Put this in its own file for import
#>
function Get-S1Agents () {
    [CmdletBinding()]
    Param(
        [Parameter()][String]$AgentName,
        [Parameter()][Int]$Limit=25,
        [Parameter()][Switch]$Infected=$false
    )

    return $s1.GetAgents($AgentName,$Limit, $Infected)
}

function Get-S1Threat ($ThreatID) {
    return $s1.GetThreat($ThreatID)
}

function Get-S1Threats () {

    return $s1.GetThreats($false)
}

function Get-S1Users () {
    [CmdletBinding()]
    Param(
        [Parameter()][String]$Email
    )
    return $s1.GetUsers($Email)
}



$s1 = [S1API]::new("", "")
$s1.Proxy = "http://192.168.150.148:8080"
$s1.ProxyUseDefaultCredentials = $true

#Get-S1Agent -AgentName fatboy | ft computerName, lastLoggedInUserName, infected
#(Get-S1Agent -AgentName DESKTOP-E42ET4I).AbortSc
#(Get-S1Threats).Unquarantine()
#(Get-S1Threat -ThreatID 417498202662931194).ForensicsExport('json')
$user = Get-S1Users
$user



# TODO: Test multiple agents being returned by Get-S1Agent or Get-S1Agents
# TODO: API Token Storage
# TODO: API Token Inline Calls
# TODO: Username & Password Token
# TODO: ^^ MULTIFACTOR!!!
# TODO: Fix Forensic Export download
