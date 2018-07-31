# API key 
# URL 

class S1API {

    [String]$URL;
    [String]$ApiKey;
    [String]$Proxy=$null;
    [Hashtable]$Headers = @{};
    [Boolean]$ProxyUseDefaultCredentials=$false;
    [HashTable]$RequestParams = @{}

    # Constructor
    S1API ([String]$URL, [String]$APIKey) {
        $this.URL = $URL
        $this.APIKey = $APIKey
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
        
        $response = Invoke-RestMethod @params

        # Consolidate the returned data in $data so it can be appended in the event
        # of pagination
        $data = $response.data
        
        # If the API wants to paginate, let it 
        if($response.pagination) 
        {
                While($data.Count -ne $response.pagination.totalItems) {
                            $this.RequestParams.Uri += "&cursor="+$response.pagination.nextCursor
                $response = Invoke-RestMethod @params
                $data += $response.data
            }
        }

        return $data
    }

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

    # TODO: Powershell 5 doesn't support optional function parameters
    [System.Object]GetAgents([String]$AgentName, [Int]$Limit,[Boolean]$Infected) {

        $agents = $this.Get('/web/api/v2.0/agents?limit={0:d0}&infected={1}&computerName__like={2}' -f ($Limit,$Infected,$AgentName))
        
        # If there are no agents, return an empty Hashtable
        if(!$agents) {
            return $null
        }

        # Cast all the returned agents as S1Agent objects
        $agents = $agents | % {
            [S1Agent]::new($s1, $_)
        }
        return $agents
    }

    [System.Object]GetThreats([Boolean]$Resolved) {

        $threats = $this.Get('/web/api/v2.0/threats')

        if(!$threats) {
            return $null
        }

        # Cast all the returned threats as S1Threat objects
        $threats = $threats | % {
            [S1Threat]::new($s1, $_)
        }
        return $threats
    }
    
}


<#
The SentinelOne Threat object, gets fed threat data
#>
class S1Threat {

    [System.Object]$Data;
    [S1API]$s1; 

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
    }

    # Marks the threat as Benign
    # /apidoc/#!/Threats/post_web_api_v2_0_threats_mark_as_benign
    [boolean]MarkAsBenign() {
        $body = @{
            "filter" = @{
                "ids" = @($this.id);
                "contentHash"=$this.fileContentHash;
            }
        } | ConvertTo-Json

        try {
            $result = $this.s1.Post('/web/api/v2.0/threats/mark-as-benign', $body)
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }

    }

    [boolean]Quarantine() {
        $body = @{
            "filter" = @{
                "ids" = @($this.id);
                "contentHash"=$this.fileContentHash;
            }
        } | ConvertTo-Json
        

        try {
            $result = $this.s1.Post('/web/api/v2.0/threats/mitigate/quarantine', $body)
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    [boolean]Unquarantine() {
        $body = @{
            "filter" = @{
                "ids" = @($this.id);
                "contentHash"=$this.fileContentHash;
            }
        } | ConvertTo-Json
        

        try {
            $result = $this.s1.Post('/web/api/v2.0/threats/mitigate/un-quarantine', $body)
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

}


<# 
The SentinelOne Agent object, gets fed agent data
#>
class S1Agent {

    [System.Object]$Data;
    [S1API]$s1;

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
    }

    # Disconnects the Agent from the network
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_disconnect
    [boolean]DisconnectNetwork() {

        $body = @{
            "filter" = @{
                "ids" = @($this.id)
            }
        } | ConvertTo-Json

        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/disconnect', $body)
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
        
    }

    # Connects the Agent to the network
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_connect
    [boolean]ConnectNetwork() {

        $body = @{
            "filter" = @{
                "ids" = @($this.id)
            }
        } | ConvertTo-Json
        
        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/connect', $body)
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Initiates a Full Disk Scan
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_initiate_scan
    [boolean]InitiateScan() {

        $body = @{
            "filter" = @{
                "ids" = @($this.id)
            }
        } | ConvertTo-Json
        
        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/initiate-scan', $body)
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Initiates a Full Disk Scan
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_abort_scan
    [boolean]AbortScan() {

        $body = @{
            "filter" = @{
                "ids" = @($this.id)
            }
        } | ConvertTo-Json
        
        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/abort-scan', $body)
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Lists all the processes on the Agent
    # /apidoc/#!/Agents/get_web_api_v2_0_agents_processes
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
    [boolean]SendMessage($message) {

        $body = @{
            "filter" = @{
                "ids" = @($this.id)
            };
            "data" = @{
                "message" = $message;
            };
        } | ConvertTo-Json
        
        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/broadcast?ids='+$this.id, $body)
            return $result
        } catch {
            $_.Exception.Message
            return $null
        }
    }

    # Approve an Uninstall Request
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_approve_uninstall
    [boolean]ApproveUninstall() {
        $body = @{
            "filter" = @{
                "ids" = @($this.id)
            }
        } | ConvertTo-Json
        
        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/approve-uninstall', $body)
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Reject an Uninstall Request
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_reject_uninstall
    [boolean]RejectUninstall() {
        $body = @{
            "filter" = @{
                "ids" = @($this.id)
            }
        } | ConvertTo-Json
        
        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/reject-uninstall', $body)
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

    # Decommission Agent
    # /apidoc/#!/Agent_Actions/post_web_api_v2_0_agents_actions_decommision
    [boolean]Decommission() {
        $body = @{
            "filter" = @{
                "ids" = @($this.id)
            }
        } | ConvertTo-Json
        
        try {
            $result = $this.s1.Post('/web/api/v2.0/agents/actions/decommision', $body)
            return $true
        } catch {
            $_.Exception.Message
            return $false
        }
    }

}


$s1 = [S1API]::new("", "")
#$s1.Proxy = ""
#$s1.ProxyUseDefaultCredentials = $true

#Get-S1Agent -AgentName $env:COMPUTERNAME





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
Preferable to user the Cmdlets over the direct $s1.GetAgent call, it requires
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

function Get-S1Threats () {

    return $s1.GetThreats($false)
}


#Get-S1Agent -AgentName fatboy | ft computerName, lastLoggedInUserName, infected
(Get-S1Threats).Unquarantine()


# TODO: Test multiple agents being returned by Get-S1Agent or Get-S1Agents
# TODO: Threat class
# TODO: API Token Storage
# TODO: API Token Inline Calls
# TODO: Username & Password Token
# TODO: ^^ MULTIFACTOR!!!
