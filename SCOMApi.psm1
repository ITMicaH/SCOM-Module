Using namespace Microsoft.PowerShell.Commands

#region Helperfunctions

<#
.Synopsis
   Invoke REST method for SCOM API session
.EXAMPLE
   Invoke-SCOMRestMethod -Uri data/alert -Body $JSON
#>
function Invoke-SCOMRestMethod
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Uri for the request minus the base url
        [Parameter(Mandatory,
                   Position=0)]
        [string]
        $Uri,

        # Body for the request
        [Parameter(Position=1)]
        [string]
        $Body,

        [Parameter(Position=2)]
        [WebRequestMethod]
        $Method = 'POST'
    )

    Begin
    {
        Write-Verbose "Checking SCOM API session"
        If (!$SCOMSession)
        {
            Throw "No session to a SCOM API detected. Run command New-SCOMSession first."
        }
        elseif ((Get-Date $SCOMSession.ExpiryTime) -lt (Get-Date))
        {
            Write-Verbose "Session expired, refreshing"
            If ($SCOMSession.Credential)
            {
                New-SCOMSession -Server $SCOMSession.Server -Credential $SCOMSession.Credential
            }
            else
            {
                New-SCOMSession -Server $SCOMSession.Server
            }
        }
    }
    Process
    {
        $Splat = @{
            Uri = "https://$($SCOMSession.Server)/OperationsManager/$Uri"
            Method = $Method
            Headers = $SCOMSession.Headers
            ContentType = $SCOMSession.ContentType
            WebSession = $SCOMSession.WebSession
        }
        if ($PSBoundParameters.Body)
        {
            $Splat.Add('Body',$Body)
        }
        Write-Verbose "Invoking the REST method"
        try
        {
            Invoke-RestMethod @Splat -ErrorAction Stop
        }
        catch
        {
            $ErrMessage = $_.ErrorDetails.Message | ConvertFrom-Json | select -ExpandProperty errorMessage
            if ($ErrMessage -match 'expired')
            {
                Write-Verbose "Session expired, refreshing"
                If ($SCOMSession.Credential)
                {
                    New-SCOMSession -Server $SCOMSession.Server -Credential $SCOMSession.Credential
                }
                else
                {
                    New-SCOMSession -Server $SCOMSession.Server
                }
                #Invoke-RestMethod @Splat
                Invoke-SCOMRestMethod @PSBoundParameters
            }
            else
            {
                Write-Error $_
            }
        }
    }
}

<#
.Synopsis
   Converts a hashtable into a criteria string
#>
function ConvertTo-Criteria
{
    [OutputType([string])]
    Param
    (
        # Critaria hashtable
        [Parameter(Mandatory)]
        [hashtable]
        $Filter
    )

    $Array = [System.Collections.ArrayList]::new()
    foreach ($Item in $Filter.Keys)
    {
        If ($Filter.$Item -is [enum])
        {
            $Value = $Filter.$Item.value__
        }
        else
        {
            $Value = $Filter.$Item
        }
        $null = $Array.Add("($Item = '$Value')")
    }
    if ($Array.Count -gt 1)
    {
        return "($($Array -join ' AND '))"
    }
    else
    {
        return $Array[0].Trim('\(\)')
    }
}

#endregion Helperfunctions

<#
.Synopsis
   Start new SCOM API session
.DESCRIPTION
   Start new SCOM API session using provided server and possibly credentials
.EXAMPLE
   New-SCOMSession -Server SCOMServer -Credential Contoso\User001
.EXAMPLE
   New-SCOMSession -Server SCOMServer
#>
function New-SCOMSession
{
    [CmdletBinding()]
    Param
    (
        # Name of the SCOM server
        [Parameter(Mandatory,
                   Position=0)]
        [string]
        $Server,

        # Credential for connection
        [Parameter(Position=1)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    # Set the Header and the Body
    $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $Headers.Add('Content-Type', 'application/json; charset=utf-8')

    If ($PSBoundParameters['Credential'])
    {
        $bodyraw = "AuthenticationMode:$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($bodyraw)
        $EncodedText =[Convert]::ToBase64String($Bytes)
        $jsonbody = $EncodedText | ConvertTo-Json
    }
    else
    {
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes("Windows")
        $EncodedText = [Convert]::ToBase64String($Bytes)
    }
    $JSONBody = $EncodedText | ConvertTo-Json

    $Params = @{
        Method = 'Post'
        Uri = "http://$Server/OperationsManager/authenticate"
        Headers = $Headers
        body = $JSONBody
        SessionVariable = 'WebSession'
        UseDefaultCredentials = $true
    }

    # Authentication
    $Authentication = Invoke-RestMethod @Params -ErrorAction Stop

    # Initiate the Cross-Site Request Forgery (CSRF) token, this is to prevent CSRF attacks
    $CSRFtoken = $WebSession.Cookies.GetCookies($Params.Uri) | ? { $_.Name -eq 'SCOM-CSRF-TOKEN' }
    $Headers.Add('SCOM-CSRF-TOKEN', [System.Web.HttpUtility]::UrlDecode($CSRFtoken.Value))

    $SCOMSession = [pscustomobject]@{
        Server = $Server
        Credential = $Credential
        Headers = $Headers
        ContentType = "application/json"
        WebSession = $WebSession
        ExpiryTime = $Authentication.expiryTime
    }
    New-Variable -Name SCOMSession -Value $SCOMSession -Scope Script -Force #-Visibility Private
}

<#
.Synopsis
   Get SCOM Alerts
.DESCRIPTION
   Long description
.EXAMPLE
   Get-SCOMAlert
   Retreives all SCOM alerts
.EXAMPLE
   Get-SCOMAlert -Severity Critical -Class 'SQL Server'
#>
function Get-SCOMAlert
{
    [CmdletBinding(DefaultParameterSetName='Default')]
    [OutputType([int])]
    Param
    (
        # Alert severity level
        [Parameter(ParameterSetName='Default')]
        [Severity]
        $Severity,

        # State of the resolution
        [Parameter(ParameterSetName='Default')]
        [State]
        $State,

        # SCOM class
        [Parameter(ValueFromPipeline,ParameterSetName='Default')]
        [SCOMClass]
        $Class,

        # SCOM group for scoping (SCOM 2022 only)
        [Parameter(ValueFromPipeline,ParameterSetName='Default')]
        [SCOMGroup]
        $Group,

        # Criteria for searching alerts
        [Parameter(ParameterSetName='Custom')]
        [hashtable]
        $Filter,

        # Display all possible properties
        [switch]
        $AllProperties
    )

    Begin
    {
        $Columns = Invoke-SCOMRestMethod -Uri resources/alertColumns -Method GET
    }
    Process
    {
        # The query which contains the alert criteria
        $Query = @{ 
            criteria = "Name LIKE '%'"
            displayColumns = "severity", "monitoringobjectdisplayname", "name", "description", "age", "repeatcount", "resolutionstate"
        }
        $Criteria = $null
        If ($PSBoundParameters.Keys -contains 'Severity')
        {
            $Criteria = "Severity = '$($Severity.value__)'"
        }
        If ($PSBoundParameters.Keys -contains 'State' -and !$Criteria)
        {
            $Criteria = "ResolutionState = '$($State.value__)'"
        }
        elseif ($PSBoundParameters.Keys -contains 'State')
        {
            $Criteria = "(($Criteria) AND (ResolutionState = '$($State.value__)'))"
        }
        If ($PSBoundParameters.Class -and !$Criteria)
        {
            $Criteria = "ClassId = '$($Class.Id)'"
        }
        elseif ($PSBoundParameters.Class)
        {
            $Criteria = "(($Criteria) AND (ClassId = '$($Class.Id)'))"
        }
        If ($PSBoundParameters.Filter)
        {
            $Criteria = ConvertTo-Criteria -Filter $Filter
        }
        If ($Criteria)
        {
            $Query.criteria = $Criteria
        }
        if ($PSBoundParameters.AllProperties)
        {
            $Query.displayColumns = $Columns.id
        }
        if ($PSBoundParameters.Group)
        {
            $Query.groupId = $Group.Id
        }
        # Convert query to JSON format
        $JSONQuery = $Query | ConvertTo-Json

        Invoke-SCOMRestMethod -Uri data/alert -Body $JSONQuery | 
            select -ExpandProperty rows
    }
    End
    {
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-SCOMAlertInfo
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Alias('id')]
        [guid]
        $AlertID
    )

    Process
    {
        Invoke-SCOMRestMethod -Uri data/alertInformation/$AlertID -Method Get
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-SCOMMonitor
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Name of the monitor
        [SupportsWildcards()]
        [string]
        $Name
    )

    Process
    {
        # The query which contains the monitor criteria
        If ($PSBoundParameters.Name)
        {
            $Query = "DisplayName LIKE '$($Name.Replace('*','%'))'"
        }
        else
        {
            $Query = "DisplayName LIKE '%'"
        }

        # Convert query to JSON format
        $JSONQuery = $Query | ConvertTo-Json

        Invoke-SCOMRestMethod -Uri data/class/monitors -Body $JSONQuery | select -ExpandProperty rows
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-SCOMGroup
{
    [CmdletBinding()]
    [OutputType([SCOMGroup])]
    Param
    (
        # Name of the SCOM group
        [SupportsWildcards()]
        [string]
        $Name
    )

    Begin
    {
    }
    Process
    {
        # The query which contains the group criteria
        If ($PSBoundParameters.Name)
        {
            $Query = "DisplayName LIKE '$($Name.Replace('*','%'))'"
        }
        else
        {
            $Query = "DisplayName LIKE '%'"
        }

        # Convert query to JSON format
        $JSONQuery = $Query | ConvertTo-Json

        [SCOMGroup[]]$Output = Invoke-SCOMRestMethod -Uri data/scomGroups -Body $JSONQuery | select -ExpandProperty scopeDatas
        return $Output
    }
    End
    {
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-SCOMClass
{
    [CmdletBinding()]
    [OutputType([SCOMClass])]
    Param
    (
        # Name of the SCOM class
        [SupportsWildcards()]
        [string]
        $Name
    )

    Begin
    {
    }
    Process
    {
        # The query which contains the class criteria
        If ($PSBoundParameters.Name)
        {
            $Query = "DisplayName LIKE '$($Name.Replace('*','%'))'"
        }
        else
        {
            $Query = "DisplayName LIKE '%'"
        }

        # Convert query to JSON format
        $JSONQuery = $Query | ConvertTo-Json

        [SCOMClass[]]$Output = Invoke-SCOMRestMethod -Uri data/scomClasses -Body $JSONQuery | select -ExpandProperty scopeDatas
        return $Output
    }
    End
    {
    }
}

#region enums

Enum Severity
{
    Information
    Warning
    Critical
}

Enum State
{
    New = 0
    Awaiting = 247
    Assigned =  248
    Scheduled = 250
    Resolved = 254
    Closed = 255
}

Enum Priority
{
    Low
    Medium
    High
}

#endregion enums

#region Classes

class SCOMClass
{
   [guid]   $Id
   [string] $DisplayName
   [string] $ClassName
   [string] $Path
   [string] $FullName

   # Constructor object
   SCOMGroup ([PSCustomObject] $Class)
   {
       $this.Id = $Class.id
       $this.DisplayName = $Class.displayName
       $this.ClassName = $Class.className
       $this.Path = $Class.path
       $this.FullName = $Class.fullName  
   }

   # Constructor for name
   SCOMGroup ([string]$Name)
   {
        $Class = Get-SCOMClass -Name $Name
        if ($Class -and $Class.Count -eq 1)
        {
            $this.Id = $Class.id
            $this.DisplayName = $Class.displayName
            $this.ClassName = $Class.className
            $this.Path = $Class.path
            $this.FullName = $Class.fullName 
        }
        else
        {
            Write-Error -Exception "Unable to find class $Name" -Category ObjectNotFound
            return
        }
   }
}

class SCOMGroup
{
   [guid]   $Id
   [string] $DisplayName
   [string] $ClassName
   [string] $Path
   [string] $FullName

   # Constructor object
   SCOMGroup ([PSCustomObject] $Group)
   {
       $this.Id = $Group.id
       $this.DisplayName = $Group.displayName
       $this.ClassName = $Group.className
       $this.Path = $Group.path
       $this.FullName = $Group.fullName  
   }

   # Constructor for name
   SCOMGroup ([string]$Name)
   {
        $Group = Get-SCOMClass -Name $Name
        if ($Group -and $Group.Count -eq 1)
        {
            $this.Id = $Group.id
            $this.DisplayName = $Group.displayName
            $this.ClassName = $Group.className
            $this.Path = $Group.path
            $this.FullName = $Group.fullName 
        }
        else
        {
            Write-Error -Exception "Unable to find class $Name" -Category ObjectNotFound
            return
        }
   }
}


#endregion Classes
