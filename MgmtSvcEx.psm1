#requires -version 4
#requires -module MgmtSvcAdmin

#region load assembly
Add-Type -AssemblyName 'System.ServiceModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
Add-Type -AssemblyName 'System.IdentityModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
#endregion load assembly

#region extend typedata
Update-TypeData -TypeName Microsoft.WindowsAzure.Server.Management.Plan -MemberType AliasProperty -MemberName PlanId -Value Id -Force
#endregion extend typedata

#region private variables
$Token = $null
$Headers = $null
$ApiUrl = $null
$Port = $null
$IgnoreSSL = $false
$OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
#endregion private variables

#region cleanup PSDefaultParameterValues
function CleanPSDefaultParameterValues {
    [void] $global:PSDefaultParameterValues.Remove("*-MgmtSvc*:AdminUri")
    [void] $global:PSDefaultParameterValues.Remove("*-MgmtSvc*:Token")
    [void] $global:PSDefaultParameterValues.Remove("*-MgmtSvc*:DisableCertificateValidation")
}
CleanPSDefaultParameterValues
#endregion cleanup PSDefaultParameterValues

#region internal functions
function IgnoreSSL {
    Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
}

function TestJWTClaimNotExpired {
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [String] $Token
    )
    #based on functions by Shriram MSFT found on technet: https://gallery.technet.microsoft.com/JWT-Token-Decode-637cf001
    process {
        try {
            if ($Token.split('.').count -ne 3) {
                throw 'Invalid token passed, run Get-MgmtSvcExToken to fetch a new one'
            }
            $TokenData = $token.Split('.')[1] | ForEach-Object -Process {
                $data = $_ -as [String]
                $data = $data.Replace('-', '+').Replace('_', '/')
                switch ($data.Length % 4) {
                    0 { break }
                    2 { $data += '==' }
                    3 { $data += '=' }
                    default { throw New-Object -TypeName ArgumentException -ArgumentList ('data') }
                }
                [System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($data)) | ConvertFrom-Json
            }
            #JWT Reference Time
            $Ref = [datetime]::SpecifyKind((New-Object -TypeName datetime -ArgumentList ('1970',1,1,0,0,0)),'UTC')
            #UTC time right now - Reference time gives amount of seconds to check against
            $CheckSeconds = [System.Math]::Round(([datetime]::UtcNow - $Ref).totalseconds)
            if ($TokenData.exp -gt $CheckSeconds) {
                Write-Output -InputObject $true
            } else {
                Write-Output -InputObject $false
            }
        } catch {
            Write-Error -ErrorRecord $_
        }
    }
}

function PreFlight {
    [CmdletBinding()]
    param (
        [Switch] $IncludeConnection
    )

    Write-Verbose -Message 'Validating Token Acquired'
    if (($null -eq $script:Token) -or ($null -eq $script:Headers)) {
        throw 'Token was not acquired, run Get-MgmtSvcExToken first!'
    }

    Write-Verbose -Message 'Validating Token not expired'
    if (!(TestJWTClaimNotExpired -Token $script:Token)) {
        throw 'Token has expired, fetch a new one!'
    }

    if ($IncludeConnection) {
        Write-Verbose -Message 'Validating if connection is set'
        if ($null -eq $script:APIUrl) {
            throw 'No connection has been made to API yet, run Connect-MgmtSvcAPI first!'
        }
    }
}

function ConvertToUIntTest {
    param (
        [System.String] $ParamName,
        [System.String] $StringInput
    )
    if ($StringInput -ne [System.String]::Empty) {
        try {
            [void] [uint32] $StringInput
        } catch {
            Write-Error -Message ('{0} value should be convertable to UInt32 but value is {1}' -f $ParamName,$StringInput) -ErrorAction Stop
        }
    }
}
#endregion internal functions

#region public functions
function Get-MgmtSvcExAPICertificate {
    [CmdletBinding()]
    param (

    )
    try {
        
        $request = [System.Net.WebRequest]::Create("$ApiUrl`:$Port")
        $OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
        Write-Warning -Message 'IgnoreSSL defined by Connect-WAPAPI, Certificate errors will be ignored!'
        #Change Certificate Policy to ignore
        IgnoreSSL
        
        $null = $request.GetResponse()
        $servicePoint = $request.ServicePoint
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2](
            $servicePoint.Certificate.Export(
                [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
            )
        )
        Write-Output -InputObject $certificate
    } catch {
        Write-Error -ErrorRecord $_ -ErrorAction Stop
    } finally {
        [System.Net.ServicePointManager]::CertificatePolicy = $OriginalCertificatePolicy
    }
}

#proxy function of Get-MgmtSvcToken
function Get-MgmtSvcExToken {
    <#
    
    .ForwardHelpTargetName MgmtSvcAdmin\Get-MgmtSvcToken
    .ForwardHelpCategory Cmdlet
    
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [Microsoft.WindowsAzure.Admin.PowerShell.TokenType]
        ${Type},
    
        [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [uri]
        ${AuthenticationSite},
    
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [pscredential]
        ${User},
    
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [uri]
        ${AdfsAddress},
    
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [uri]
        ${AdfsRealm},
    
        [switch]
        ${DisableCertificateValidation},

        [switch]
        ${PassThru}
    )
    begin {
        try {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer)) {
                $PSBoundParameters['OutBuffer'] = 1
            }
            #tokens is only for dealing with Admin API. so hardcoding
            [void]$PSBoundParameters.Add('ClientRealm','http://azureservices/AdminSite')
            #PassThru is not original switch, removing from binding to avoid cmdlet error
            [void]$PSBoundParameters.Remove('PassThru')
            if ($null -eq $AdfsRealm -and $Type -eq [Microsoft.WindowsAzure.Admin.PowerShell.TokenType]::Adfs) {
                #AdfsRealm is required by Get-MgmtSvcToken but not required for Adfs Type (wrong validation) so trying relaxed approach
                [void] $PSBoundParameters.Add('AdfsRealm',$AdfsAddress)
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('MgmtSvcAdmin\Get-MgmtSvcToken', [System.Management.Automation.CommandTypes]::Cmdlet)
            $scriptCmd = {
                & $wrappedCmd @PSBoundParameters | %{
                    if ($null -ne $_) {
                        Set-Variable -Name Headers -Scope 1 -Value @{
                            Authorization = "Bearer $_"
                            'x-ms-principal-id' = $User.UserName
                            Accept = 'application/json;odata=fullmetadata'
                        }
                        Set-Variable -Name Token -Value $_ -Scope 1
                        if ($PassThru) {
                            Write-Output -InputObject $_
                        }
                    }
                }
            }
            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($PSCmdlet)
        } catch {
            throw
        }
    } process {
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
    } end {
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
    }
}

function Connect-MgmtSvcExAPI {
    <#
    .SYNOPSIS
        Connects to WAP Admin API.

    .PARAMETER Url
        The URL of either the Admin API.

    .PARAMETER Port
        The Port on which the API is listening (default to Admin API port 30004).

    .PARAMETER IgnoreSSL
        When using self-signed certificates, SSL validation will be ignored when this switch is enabled.
        All functions relying on the connection will inherit the SSL setting.

    .EXAMPLE
        PS C:\>$URL = 'https://adminapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-MgmtSvcExToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-MgmtSvcExAPI -URL $URL

        This will connect to the WAP Admin API on its default port.

    .EXAMPLE
        PS C:\>$URL = 'https://adminapi.mydomain.com'
        PS C:\>$creds = Get-Credential
        PS C:\>Get-MgmtSvcExToken -Credential $creds -URL 'https://sts.adfs.com' -ADFS
        PS C:\>Connect-MgmtSvcExAPI -URL $URL -Port 443

        This will connect to the Admin API on a non default port 443.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $Url,

        [Int] $Port = 30004,

        [Switch] $IgnoreSSL
    )
    try {
        if ($IgnoreSSL) {
            Write-Warning -Message 'IgnoreSSL switch defined. Certificate errors will be ignored througout this PowerShell session!'
            #Change Certificate Policy to ignore
            IgnoreSSL
        }

        PreFlight

        $TestURL = '{0}:{1}/subscriptions/' -f $Url,$Port
        Write-Verbose -Message "Constructed Connection URL: $TestURL"

        $Result = Invoke-WebRequest -Uri $TestURL -Headers $script:Headers -UseBasicParsing -ErrorVariable 'ErrCon'
        if ($Result) {
            Write-Verbose -Message 'Successfully connected'
            Set-Variable -Name APIUrl -Value $Url -Scope 1
            Set-Variable -Name Port -Value $Port -Scope 1
            Set-Variable -Name IgnoreSSL -Value $IgnoreSSL -Scope 1
            CleanPSDefaultParameterValues
            [void] $global:PSDefaultParameterValues.Add("*-MgmtSvc*:AdminUri","$Url`:$Port")
            [void] $global:PSDefaultParameterValues.Add("*-MgmtSvc*:Token",$script:Token)
            if ($IgnoreSSL) {
                [void] $global:PSDefaultParameterValues.Add("*-MgmtSvc*:DisableCertificateValidation",$true)
            }
        } else {
            Write-Verbose -Message 'Connection unsuccessfull' -Verbose
            Set-Variable -Name APIUrl -Value $null -Scope 1
            Set-Variable -Name Port -Value $null -Scope 1
            Set-Variable -Name IgnoreSSL -Value $false -Scope 1
            CleanPSDefaultParameterValues
            throw $ErrCon
        }
    } catch {
        Write-Error -ErrorRecord $_
    }
}

function Get-MgmtSvcExCloud {
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName='List')]
    param (
        [Parameter(Mandatory,ValueFromPipeline,ParameterSetName='Named')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Name
    )
    process {
        try {
            PreFlight -IncludeConnection
            $URI = '{0}:{1}/services/systemcenter/SC2012R2/VMM/Microsoft.Management.Odata.svc/Clouds()' -f $script:APIUrl,$script:Port
            Write-Verbose -Message "Constructed Cloud URI: $URI"

            $Clouds = Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get
            foreach ($C in $Clouds.Value) {
                if ($PSCmdlet.ParameterSetName -eq 'Named' -and $C.Name -ne $Name) {
                    continue
                }
                $C.PSObject.TypeNames.Insert(0,'WAP.AdminCloud')
                Write-Output -InputObject $C
            }
        } catch {
            Write-Error -ErrorRecord $_
        }
    }
}

function Get-MgmtSvcExLogicalNetwork {
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName='List')]
    param (
        [Parameter(Mandatory,ParameterSetName='Named')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Name,

        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.AdminCloud')]
        [PSCustomObject] $Cloud
    )
    process {
        try {
            PreFlight -IncludeConnection
            
            $URI = '{0}:{1}/services/systemcenter/SC2012R2/VMM/Microsoft.Management.Odata.svc/{2}' -f $script:APIUrl,$script:Port,$Cloud.'LogicalNetworks@odata.navigationLinkUrl'
            Write-Verbose -Message "Constructed LogicalNetwork URI: $URI"
            $Networks = Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get
            foreach ($N in $Networks.Value) {
                if ($PSCmdlet.ParameterSetName -eq 'Named' -and $N.Name -ne $Name) {
                    continue
                }
                $N.PSObject.TypeNames.Insert(0,'WAP.AdminLogicalNetwork')
                Write-Output -InputObject $N
            }
        } catch {
            Write-Error -ErrorRecord $_
        }
    }
}

function Get-MgmtSvcExVMNetwork {
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName='List')]
    param (
        [Parameter(Mandatory,ParameterSetName='Named')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Name,

        [Parameter(Mandatory,ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.AdminCloud')]
        [PSCustomObject] $Cloud
    )
    process {
        try {
            PreFlight -IncludeConnection
            $LogicalNetworks = $Cloud | Get-MgmtSvcExLogicalNetwork
            $URI = '{0}:{1}/services/systemcenter/SC2012R2/VMM/Microsoft.Management.Odata.svc/VMNetworks()?$filter=StampId eq guid''{2}''' -f $script:APIUrl,$script:Port,$Cloud.StampId
            Write-Verbose -Message "Constructed VMNetworks URI: $URI"

            $Networks = Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get
            foreach ($N in $Networks.Value) {
                if ($LogicalNetworks.ID -notcontains $N.LogicalNetworkId) {
                    continue
                }
                if ($PSCmdlet.ParameterSetName -eq 'Named' -and $N.Name -ne $Name) {
                    continue
                }
                $N.PSObject.TypeNames.Insert(0,'WAP.AdminVMNetwork')
                Write-Output -InputObject $N
            }
        } catch {
            Write-Error -ErrorRecord $_
        }
    }
}

function Get-MgmtSvcExVMTemplate {
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName='List')]
    param (
        [Parameter(Mandatory,ParameterSetName='Named')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Name
    )
    process {
        try {
            PreFlight -IncludeConnection
            $URI = '{0}:{1}/services/systemcenter/SC2012R2/VMM/Microsoft.Management.Odata.svc/VMTemplates()' -f $script:APIUrl,$script:Port
            Write-Verbose -Message "Constructed VMTemplates URI: $URI"

            $Templates = Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get
            foreach ($T in $Templates.Value) {
                if ($PSCmdlet.ParameterSetName -eq 'Named' -and $T.Name -ne $Name) {
                    continue
                }
                if ($T.OSType -eq 'Other') {
                    continue
                }
                $T.PSObject.TypeNames.Insert(0,'WAP.AdminVMTemplate')
                Write-Output -InputObject $T
            }
        } catch {
            Write-Error -ErrorRecord $_
        }
    }
}

function Get-MgmtSvcExHardwareProfile {
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName='List')]
    param (
        [Parameter(Mandatory,ParameterSetName='Named')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Name
    )
    process {
        try {
            PreFlight -IncludeConnection
            $URI = '{0}:{1}/services/systemcenter/SC2012R2/VMM/Microsoft.Management.Odata.svc/HardwareProfiles()' -f $script:APIUrl,$script:Port
            Write-Verbose -Message "Constructed HardwareProfiles URI: $URI"

            $HWProfiles = Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get
            foreach ($P in $HWProfiles.value) {
                if ($PSCmdlet.ParameterSetName -eq 'Named' -and $P.Name -ne $Name) {
                    continue
                }
                $P.PSObject.TypeNames.Insert(0,'WAP.AdminHardwareProfile')
                Write-Output -InputObject $P
            }
        } catch {
            Write-Error -ErrorRecord $_
        }
    }
}

function Get-MgmtSvcExGalleryItem {
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName='List')]
    param (
        [Parameter(Mandatory,ParameterSetName='Named')]
        [ValidateNotNullOrEmpty()]
        [System.String] $Name,

        [Parameter(ParameterSetName='List')]
        [Parameter(ParameterSetName='Named')]
        [System.String] $Publisher
    )
    process {
        try {
            PreFlight -IncludeConnection
            $URI = '{0}:{1}/services/systemcenter/SC2012R2/Admin/GalleryAdminService.svc/GalleryPackages()' -f $script:APIUrl,$script:Port
            Write-Verbose -Message "Constructed GalleryItem URI: $URI"

            $GalleryItems = Invoke-RestMethod -Uri $URI -Headers $script:Headers -Method Get
            foreach ($G in $GalleryItems.value) {
                if ($PSCmdlet.ParameterSetName -eq 'Named' -and $G.Name -ne $Name) {
                    continue
                }
                if ($PSBoundParameters.Keys.Contains('Publisher')) {
                    if ($G.Publisher -ne $Publisher) {
                        continue
                    }
                }
                $G.PSObject.TypeNames.Insert(0,'WAP.AdminGalleryItem')
                Write-Output -InputObject $G
            }
        } catch {
            Write-Error -ErrorRecord $_
        }
    }
}

function New-MgmtSvcExQuotaSettingSCActions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.AdminCloud')]
        [PSCustomObject] $Cloud,

        [switch] $Checkpoint,

        [switch] $CheckpointRestoreOnly,

        [switch] $SaveVMState,

        [switch] $LibraryStoreAndDeploy,

        [switch] $ConsoleConnect,

        #default = unlimited
        [System.String] $MaximumNetwork = [System.String]::Empty,

        #default = unlimited Mb/s
        [System.String] $MaximumBandwidthIn = [System.String]::Empty,

        #default = unlimited Mb/s
        [System.String] $MaximumBandwidthOut = [System.String]::Empty,

        [ValidateRange(0,99)]
        [uint16] $MaximumVPNConnection = 99,

        [ValidateRange(0,99)]
        [uint16] $MaximumNATConnection = 99
    )
    process {
        try {
            ConvertToUIntTest MaximumNetwork $MaximumNetwork
            ConvertToUIntTest MaximumBandwidthIn $MaximumBandwidthIn
            ConvertToUIntTest MaximumBandwidthOut $MaximumBandwidthOut

            $stringBuilder = New-Object -TypeName System.Text.StringBuilder
            #open html
            [void]$stringBuilder.Append("<Actions>`r`n")
            [void]$stringBuilder.Append("    <Stamp Id=`"{0}`">`r`n" -f $Cloud.StampId)
            
            #implicit settings

            [void]$stringBuilder.Append("        <Action>Author</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>Create</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>CreateFromVHDOrTemplate</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>AllowLocalAdmin</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>Start</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>Stop</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>PauseAndResume</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>Shutdown</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>Remove</Action>`r`n")

            #optional settings
            if ($Checkpoint) {
                [void]$stringBuilder.Append("        <Action>Checkpoint</Action>`r`n")
                [void]$stringBuilder.Append("        <Action>CheckpointRestoreOnly</Action>`r`n")
            }
            if ($CheckpointRestoreOnly -and -not $Checkpoint) {
                [void]$stringBuilder.Append("        <Action>CheckpointRestoreOnly</Action>`r`n")
            }
            if ($SaveVMState) {
                [void]$stringBuilder.Append("        <Action>Save</Action>`r`n")
            }
            if ($LibraryStoreAndDeploy) {
                [void]$stringBuilder.Append("        <Action>Store</Action>`r`n")
            }
            if ($ConsoleConnect) {
                [void]$stringBuilder.Append("        <Action>RemoteConnect</Action>`r`n")
            }

            #network settings
            [void]$stringBuilder.Append("        <Action")
            [void]$stringBuilder.Append(" MaximumNetwork=`"{0}`"" -f $MaximumNetwork)
            [void]$stringBuilder.Append(" MaximumMemberNetwork=`"{0}`"" -f $MaximumNetwork)
            [void]$stringBuilder.Append(" MaximumBandwidthIn=`"{0}`"" -f $MaximumBandwidthIn)
            [void]$stringBuilder.Append(" MaximumBandwidthOut=`"{0}`"" -f $MaximumBandwidthOut)
            [void]$stringBuilder.Append(" MaximumVPNConnection=`"{0}`"" -f $MaximumVPNConnection)
            [void]$stringBuilder.Append(" MaximumMemberVPNConnection=`"{0}`"" -f $MaximumVPNConnection)
            [void]$stringBuilder.Append(" MaximumNATConnection=`"{0}`"" -f $MaximumNATConnection)
            [void]$stringBuilder.Append(" MaximumMemberNATConnection=`"{0}`"" -f $MaximumNATConnection)
            [void]$stringBuilder.Append(">AuthorVMNetwork</Action>`r`n")

            #close up html
            [void]$stringBuilder.Append("    </Stamp>`r`n")
            [void]$stringBuilder.Append("</Actions>")
            $stringBuilder.ToString()
        } catch {
            Write-Error -ErrorRecord $_ -ErrorAction Stop
        }
    }
}

function New-MgmtSvcExQuotaSettingSCClouds {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.AdminCloud')]
        [PSCustomObject] $Cloud,

        #default = unlimited
        [System.String] $VMCount = [System.String]::Empty,

        #default = unlimited
        [System.String] $CPUCount = [System.String]::Empty,

        #default = unlimited
        [System.String] $MemoryMB = [System.String]::Empty,

        #default = unlimited
        [System.String] $StorageGB = [System.String]::Empty
    )
    process {
        #validate input
        try {
            ConvertToUIntTest VMCount $VMCount
            ConvertToUIntTest CPUCount $CPUCount
            ConvertToUIntTest MemoryMB $MemoryMB
            ConvertToUIntTest StorageGB $StorageGB

            $stringBuilder = New-Object -TypeName System.Text.StringBuilder
            #open html
            [void]$stringBuilder.Append("<Clouds>`r`n")
            [void]$stringBuilder.Append("    <Cloud Id=`"{0}`"" -f $Cloud.ID)
            [void]$stringBuilder.Append(" StampId=`"{0}`">`r`n" -f $Cloud.StampId)
            [void]$stringBuilder.Append("        <Quota>`r`n")

            #set quotas
            [void]$stringBuilder.Append("            <RoleVMCount>{0}</RoleVMCount>`r`n" -f $VMCount)
            [void]$stringBuilder.Append("            <MemberVMCount>{0}</MemberVMCount>`r`n" -f $VMCount)
            [void]$stringBuilder.Append("            <RoleCPUCount>{0}</RoleCPUCount>`r`n" -f $CPUCount)
            [void]$stringBuilder.Append("            <MemberCPUCount>{0}</MemberCPUCount>`r`n" -f $CPUCount)
            [void]$stringBuilder.Append("            <RoleMemoryMB>{0}</RoleMemoryMB>`r`n" -f $MemoryMB)
            [void]$stringBuilder.Append("            <MemberMemoryMB>{0}</MemberMemoryMB>`r`n" -f $MemoryMB)
            [void]$stringBuilder.Append("            <RoleStorageGB>{0}</RoleStorageGB>`r`n" -f $StorageGB)
            [void]$stringBuilder.Append("            <MemberStorageGB>{0}</MemberStorageGB>`r`n" -f $StorageGB)

            #close html
            [void]$stringBuilder.Append("        </Quota>`r`n")
            [void]$stringBuilder.Append("    </Cloud>`r`n")
            [void]$stringBuilder.Append("</Clouds>")
            $stringBuilder.ToString()
        } catch {
            Write-Error -ErrorRecord $_ -ErrorAction Stop
        }
    }
}

function New-MgmtSvcExQuotaSettingSCVmResources {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.Management.Automation.PSTypeName('WAP.AdminVMTemplate')]
        [PSCustomObject[]] $VMTemplate,

        [Parameter()]
        [System.Management.Automation.PSTypeName('WAP.AdminHardwareProfile')]
        [PSCustomObject[]] $HardwareProfile,

        [Parameter()]
        [System.Management.Automation.PSTypeName('WAP.AdminGalleryItem')]
        [PSCustomObject[]] $GalleryItem,

        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.PSTypeName('WAP.AdminCloud')]
        [PSCustomObject] $Cloud
    )
    process {
        #validate input
        try {
            $stringBuilder = New-Object -TypeName System.Text.StringBuilder
            #open html
            [void]$stringBuilder.Append("<Resources>`r`n")

            #add VM Templates
            foreach ($V in $VMTemplate) {
                [void]$stringBuilder.Append("    <VmTemplate Id=`"{0}`"" -f $V.ID)
                [void]$stringBuilder.Append(" StampId=`"{0}`" />`r`n" -f $Cloud.StampId)
            }

            #add hardware profiles
            foreach ($H in $HardwareProfile) {
                [void]$stringBuilder.Append("    <HardwareProfile Id=`"{0}`"" -f $H.ID)
                [void]$stringBuilder.Append(" StampId=`"{0}`" />`r`n" -f $Cloud.StampId)
            }

            #add GalleryItems
            foreach ($G in $GalleryItem) {
                [void]$stringBuilder.Append("    <GalleryItem")
                [void]$stringBuilder.Append(" Name=`"{0}`"" -f $G.Name)
                [void]$stringBuilder.Append(" Version=`"{0}`"" -f $G.Version)
                [void]$stringBuilder.Append(" Publisher=`"{0}`"" -f $G.Publisher)
                [void]$stringBuilder.Append(" StampId=`"{0}`"" -f $Cloud.StampId)
                [void]$stringBuilder.Append(" />`r`n")
            }

            #close html
            [void]$stringBuilder.Append("</Resources>")
            $stringBuilder.ToString()
        } catch {
            Write-Error -ErrorRecord $_ -ErrorAction Stop
        }
    }
}

function New-MgmtSvcExQuotaSettingSCNetworks {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.Management.Automation.PSTypeName('WAP.AdminVMNetwork')]
        [PSCustomObject[]] $Network
    )
    process {
        #validate input
        try {
            $stringBuilder = New-Object -TypeName System.Text.StringBuilder
            #open html
            [void]$stringBuilder.Append("<Networks>`r`n")

            foreach ($N in $Network) {
                [void]$stringBuilder.Append("    <Network Id=`"{0}`"" -f $N.ID)
                [void]$stringBuilder.Append(" StampId=`"{0}`" />`r`n" -f $N.StampId)
            }

            #close html
            [void]$stringBuilder.Append("</Networks>")
            $stringBuilder.ToString()
        } catch {
            Write-Error -ErrorRecord $_ -ErrorAction Stop
        }
    }
}

function New-MgmtSvcExQuotaSettingSCCustomSettings {
    [CmdletBinding()]
    param (
        [Switch] $DisableNetworkExtension,
        
        [Parameter()]
        [ValidateSet('TemplateDefined','TenantDefined','TenantDefinedPlus3Digits')]
        [System.String] $VMComputerNameSetting = 'TenantDefinedPlus3Digits',

        [Switch] $DREnabled,

        [Parameter()]
        [System.String] $Name
    )
    process {
        #validate input
        try {
            $stringBuilder = New-Object -TypeName System.Text.StringBuilder
            #open html
            [void]$stringBuilder.Append("<CustomSettings>`r`n")

            if ($DisableNetworkExtension -or ($VMComputerNameSetting -ne 'TenantDefinedPlus3Digits') -or $DREnabled -or $Name) {
                [void]$stringBuilder.Append("    <CustomSetting Key=`"{0}`"" -f [system.guid]::NewGuid().ToString())
                [void]$stringBuilder.Append(" Value=`"")

                if ($DisableNetworkExtension) {
                    [void]$stringBuilder.Append("DisableNetworkExtension,")
                }

                if ($VMComputerNameSetting -eq 'TemplateDefined') {
                    [void]$stringBuilder.Append("DisableSettingVMComputerName,")
                } elseif ($VMComputerNameSetting -eq 'TenantDefined') {
                    [void]$stringBuilder.Append("EnableSettingVMComputerName,")
                }

                if ($DREnabled) {
                    [void]$stringBuilder.Append("DREnabled,")
                }

                if ($Name) {
                    [void]$stringBuilder.Append("$Name,")
                }
                [void]$stringBuilder.Remove($stringBuilder.Length -1, 1)
                [void]$stringBuilder.Append("`" />`r`n")
            }

            #close html
            [void]$stringBuilder.Append("</CustomSettings>")
            $stringBuilder.ToString()
        } catch {
            Write-Error -ErrorRecord $_ -ErrorAction Stop
        }
    }
}

function Get-MgmtSvcExQuotaSettingSCActions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Microsoft.WindowsAzure.Server.Management.Plan] $Plan
    )
    process {
        $scServiceQuota = $Plan.ServiceQuotas | Where-Object -FilterScript {
            $_.ServiceName -eq 'systemcenter'
        }
        if ($null -eq $scServiceQuota) {
            Write-Error -Message "No SystemCenter Quota is configured for plan: $($Plan.DisplayName)" -ErrorAction Stop
        } else {
            $StringWriter = New-Object System.IO.StringWriter
            $XmlWriter = New-Object System.Xml.XmlTextWriter $StringWriter
            $XmlWriter.Formatting = "indented"
            $actions = [xml]$scServiceQuota.Settings.Where{$_.Key -eq 'Actions'}.Value
            $actions.WriteTo($XmlWriter)
            $XmlWriter.Flush()
            $StringWriter.Flush()
            $StringWriter.ToString()
        }
    }
}

function Update-MgmtSvcExQuotaSettingSCActions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Microsoft.WindowsAzure.Server.Management.Plan] $Plan,

        [bool] $Checkpoint,

        [bool] $CheckpointRestoreOnly,

        [bool] $SaveVMState,

        [bool] $LibraryStoreAndDeploy,

        [bool] $ConsoleConnect,

        #default = unlimited
        [System.String] $MaximumNetwork = [System.String]::Empty,
        
        #default = unlimited Mb/s
        [System.String] $MaximumBandwidthIn = [System.String]::Empty,
        
        #default = unlimited Mb/s
        [System.String] $MaximumBandwidthOut = [System.String]::Empty,
        
        #[ValidateRange(0,99)]
        [uint16] $MaximumVPNConnection = 99,
        
        #[ValidateRange(0,99)]
        [uint16] $MaximumNATConnection = 99
    )
    process {
        try {
            $xmlActions = [xml]($Plan | Get-MgmtSvcExQuotaSettingSCActions)
            $actionNodes = ($xmlActions | Select-Xml -XPath "//Action").Node.InnerText
            $networkNode = ($xmlActions | Select-Xml -XPath "//Action" | Where-Object -FilterScript {$_.Node.'#text' -eq 'AuthorVMNetwork'}).Node
            ConvertToUIntTest MaximumNetwork $MaximumNetwork
            ConvertToUIntTest MaximumBandwidthIn $MaximumBandwidthIn
            ConvertToUIntTest MaximumBandwidthOut $MaximumBandwidthOut

            $stringBuilder = New-Object -TypeName System.Text.StringBuilder
            # open xml
            [void]$stringBuilder.Append("<Actions>`r`n")
            [void]$stringBuilder.Append("    <Stamp Id=`"{0}`">`r`n" -f ($xmlActions | Select-Xml -XPath "//Stamp").Node.Id)

            # implicit settings
            [void]$stringBuilder.Append("        <Action>Author</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>Create</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>CreateFromVHDOrTemplate</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>AllowLocalAdmin</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>Start</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>Stop</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>PauseAndResume</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>Shutdown</Action>`r`n")
            [void]$stringBuilder.Append("        <Action>Remove</Action>`r`n")

            # optional settings
            if ($PSBoundParameters.ContainsKey('Checkpoint')) {
                if ($Checkpoint) {
                    [void]$stringBuilder.Append("        <Action>Checkpoint</Action>`r`n")
                    [void]$stringBuilder.Append("        <Action>CheckpointRestoreOnly</Action>`r`n")
                } elseif ($PSBoundParameters.ContainsKey('CheckpointRestoreOnly') -and $CheckpointRestoreOnly) {
                    [void]$stringBuilder.Append("        <Action>CheckpointRestoreOnly</Action>`r`n")
                } elseif ($PSBoundParameters.ContainsKey('CheckpointRestoreOnly') -and -not $CheckpointRestoreOnly) {
                    
                } elseif ($actionNodes -contains 'CheckpointRestoreOnly') {
                    [void]$stringBuilder.Append("        <Action>CheckpointRestoreOnly</Action>`r`n")
                }
            } elseif ($PSBoundParameters.ContainsKey('CheckpointRestoreOnly')) {
                if ($CheckpointRestoreOnly) {
                    [void]$stringBuilder.Append("        <Action>CheckpointRestoreOnly</Action>`r`n")
                }
            } else {
                if ($actionNodes -contains 'Checkpoint') {
                    [void]$stringBuilder.Append("        <Action>Checkpoint</Action>`r`n")
                    [void]$stringBuilder.Append("        <Action>CheckpointRestoreOnly</Action>`r`n")
                } elseif ($actionNodes -contains 'CheckpointRestoreOnly') {
                    [void]$stringBuilder.Append("        <Action>CheckpointRestoreOnly</Action>`r`n")
                }
            }

            if ($PSBoundParameters.ContainsKey('SaveVMState')) {
                if ($SaveVMState) {
                    [void]$stringBuilder.Append("        <Action>Save</Action>`r`n")
                }
            } elseif ($actionNodes -contains 'Save') {
                [void]$stringBuilder.Append("        <Action>Save</Action>`r`n")
            }

            if ($PSBoundParameters.ContainsKey('LibraryStoreAndDeploy')) {
                if ($LibraryStoreAndDeploy) {
                    [void]$stringBuilder.Append("        <Action>Store</Action>`r`n")
                }
            } elseif ($actionNodes -contains 'Store') {
                [void]$stringBuilder.Append("        <Action>Store</Action>`r`n")
            }

            if ($PSBoundParameters.ContainsKey('ConsoleConnect')) {
                if ($ConsoleConnect) {
                    [void]$stringBuilder.Append("        <Action>RemoteConnect</Action>`r`n")
                }
            } elseif ($actionNodes -contains 'RemoteConnect') {
                [void]$stringBuilder.Append("        <Action>RemoteConnect</Action>`r`n")
            }

            # network settings
            [void]$stringBuilder.Append("        <Action")
            if ($networkNode.MaximumNetwork -ne $MaximumNetwork) {
                [void]$stringBuilder.Append(" MaximumNetwork=`"{0}`"" -f $MaximumNetwork)
                [void]$stringBuilder.Append(" MaximumMemberNetwork=`"{0}`"" -f $MaximumNetwork)
            } else {
                [void]$stringBuilder.Append(" MaximumNetwork=`"{0}`"" -f $networkNode.MaximumNetwork)
                [void]$stringBuilder.Append(" MaximumMemberNetwork=`"{0}`"" -f $networkNode.MaximumMemberNetwork)
            }
            
            if ($networkNode.MaximumBandwidthIn -ne $MaximumBandwidthIn) {
                [void]$stringBuilder.Append(" MaximumBandwidthIn=`"{0}`"" -f $MaximumBandwidthIn)
            } else {
                [void]$stringBuilder.Append(" MaximumBandwidthIn=`"{0}`"" -f $networkNode.MaximumBandwidthIn)
            }

            if ($networkNode.MaximumBandwidthOut -ne $MaximumBandwidthOut) {
                [void]$stringBuilder.Append(" MaximumBandwidthOut=`"{0}`"" -f $MaximumBandwidthOut)
            } else {
                [void]$stringBuilder.Append(" MaximumBandwidthOut=`"{0}`"" -f $networkNode.MaximumBandwidthOut)
            }

            if ($networkNode.MaximumVPNConnection -ne $MaximumVPNConnection) {
                [void]$stringBuilder.Append(" MaximumVPNConnection=`"{0}`"" -f $MaximumVPNConnection)
                [void]$stringBuilder.Append(" MaximumMemberVPNConnection=`"{0}`"" -f $MaximumVPNConnection)
            } else {
                [void]$stringBuilder.Append(" MaximumVPNConnection=`"{0}`"" -f $networkNode.MaximumVPNConnection)
                [void]$stringBuilder.Append(" MaximumMemberVPNConnection=`"{0}`"" -f $networkNode.MaximumMemberVPNConnection)
            }

            if ($networkNode.MaximumNATConnection -ne $MaximumNATConnection) {
                [void]$stringBuilder.Append(" MaximumNATConnection=`"{0}`"" -f $MaximumNATConnection)
                [void]$stringBuilder.Append(" MaximumMemberNATConnection=`"{0}`"" -f $MaximumNATConnection)
            } else {
                [void]$stringBuilder.Append(" MaximumNATConnection=`"{0}`"" -f $networkNode.MaximumNATConnection)
                [void]$stringBuilder.Append(" MaximumMemberNATConnection=`"{0}`"" -f $networkNode.MaximumMemberNATConnection)
            }

            [void]$stringBuilder.Append(">AuthorVMNetwork</Action>`r`n")

            # close up xml
            [void]$stringBuilder.Append("    </Stamp>`r`n")
            [void]$stringBuilder.Append("</Actions>")
            $newActions = $stringBuilder.ToString()

            # update plan settings
            $quotaList = New-MgmtSvcQuotaList

            $scServiceQuota = $Plan.ServiceQuotas | Where-Object -FilterScript {
                $_.ServiceName -eq 'systemcenter'
            }

            $quota = Add-MgmtSvcListQuota -QuotaList $quotaList -ServiceName systemcenter -ServiceInstanceId $scServiceQuota.ServiceInstanceId

            $null = Add-MgmtSvcQuotaSetting -Quota $quota -Key Actions -Value $newActions

            $scServiceQuota.Settings | ForEach-Object -Process {
                if ($_.key -eq 'Actions') {
                    return
                }
                $null = Add-MgmtSvcQuotaSetting -Quota $quota -Key $_.Key -Value $_.Value
            }

            $updatePlanQuotaArgs = @{
                PlanId = $Plan.PlanId
                AdminUri = "$script:ApiUrl`:$script:Port"
                Token = $script:Token
                QuotaList = $quotaList
            }

            if ($script:IgnoreSSL) {
                [void]$updatePlanQuotaArgs.Add('DisableCertificateValidation',$true)
            }

            Update-MgmtSvcPlanQuota @updatePlanQuotaArgs
        } catch {
            Write-Error -ErrorRecord $_ -ErrorAction Stop
        }
    }
}

function Add-MgmtSvcExCoAdministrator {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Microsoft.WindowsAzure.Server.AdminManagement.AdminSubscription] $Subscription,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CoAdministratorName
    )
    process {
        $newCoAdmins = @()
        foreach ($c in $Subscription.CoAdminNames) {
            $newCoAdmins += $c
        }
        if ($CoAdministratorName -notin $newCoAdmins) {
            $newCoAdmins += $CoAdministratorName

            $updateArgs = @{
                SubscriptionId = $Subscription.SubscriptionId
                AdminUri = "$script:ApiUrl`:$script:Port"
                Token = $script:Token
                CoAdministratorName = $newCoAdmins
            }

            Update-MgmtSvcCoAdministrator @updateArgs
        } else {
            Write-Warning -Message "$CoAdministratorName is already a Co Administrator. No Action taken."
        }
    }
}

function Remove-MgmtSvcExCoAdministrator {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Microsoft.WindowsAzure.Server.AdminManagement.AdminSubscription] $Subscription,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CoAdministratorName
    )
    process {
        $newCoAdmins = @()
        foreach ($c in $Subscription.CoAdminNames) {
            if ($CoAdministratorName -eq $c) {
                continue
            }
            $newCoAdmins += $c

            $updateArgs = @{
                SubscriptionId = $Subscription.SubscriptionId
                AdminUri = "$script:ApiUrl`:$script:Port"
                Token = $script:Token
                CoAdministratorName = $newCoAdmins
            }

            Update-MgmtSvcCoAdministrator @updateArgs
        }
    }
}

#endregion public functions

#region module exports
Export-ModuleMember -Function *-MgmtSvcEx*
#endregion