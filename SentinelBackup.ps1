<#  
    .SYNOPSIS
        This PowerShell script exports Scheduled Analytic Rules, Automation Rules, Parsers and Workbooks

    .DESCRIPTION
        Exports Microsoft Sentinel Artifacts as ARM templates from the selected Microsoft Sentinel Workspace
    
    .PARAMETER TenantID,ClientID,ClientSecret,SubscriptionID,SentinelWorkspaceName
        Required parameter 
    
    .NOTES
        LASTEDIT: 17-08-2022    
#>

# below SP needs contributor permission on the ResourceGroup.
$ClientID =$Env:ClientId
$ClientSecret=$Env:ClientSecret
$SubscriptionID=$Env:SubscriptionID
$TenantID =$Env:TenantID;
$SentinelWorkspaceName =$Env:SentinelWorkspaceName;
$BackupFolderName =$Env:BackupFolderName;
$NotificationURL =$Env:ActionMonitoringUrl;

git config --global user.email "rap@open.ch" # any values will do, if missing commit will fail
git config --global user.name "Build user"

"Select a branch "
git checkout main 2>&1 | write-host # need the stderr redirect as some git command line send none error output here
git pull

<# If CommanVariable.json not used
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] $TenantID ,
	[Parameter(Mandatory = $true)] $SubscriptionID,   
	[Parameter(Mandatory = $true)] $SentinelWorkspaceName   
)
#>
#region Helper Functions
#region Helper Functions
enum Kind {
    Scheduled
    Fusion
    MLBehaviorAnalytics
    MicrosoftSecurityIncidentCreation
}
function Write-Log {
    <#
    .DESCRIPTION 
    Write-Log is used to write information to a log file and to the console.
    
    .PARAMETER Severity
    parameter specifies the severity of the log message. Values can be: Information, Warning, or Error. 
    #>

    [CmdletBinding()]
    param(
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [string]$LogFileName,
 
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Severity = 'Information'
    )
    # Write the message out to the correct channel											  
    switch ($Severity) {
        "Information" { Write-Host $Message -ForegroundColor Green }
        "Warning" { Write-Host $Message -ForegroundColor Yellow }
        "Error" { Write-Host $Message -ForegroundColor Red }
    } 											  
    try {
        [PSCustomObject]@{
            Time     = (Get-Date -f g)
            Message  = $Message
            Severity = $Severity
        } | Export-Csv -Path "$PSScriptRoot\$LogFileName" -Append -NoTypeInformation -Force
    }
    catch {
        Write-Error "An error occurred in Write-Log() method" -ErrorAction SilentlyContinue		
    }    
}

Function Get-RequiredModules {
    <#
    .DESCRIPTION 
    Get-Required is used to install and then import a specified PowerShell module.
    
    .PARAMETER Module
    parameter specifices the PowerShell module to install. 
    #>

    [CmdletBinding()]
    param (        
        [parameter(Mandatory = $true)] $Module        
    )
    
    try {
        $installedModule = Get-InstalledModule -Name $Module -ErrorAction SilentlyContinue       

        if ($null -eq $installedModule) {
            Write-Log -Message "The $Module PowerShell module was not found" -LogFileName $LogFileName -Severity Warning
            #check for Admin Privleges
            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

            if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                #Not an Admin, install to current user            
                Write-Log -Message "Can not install the $Module module. You are not running as Administrator" -LogFileName $LogFileName -Severity Warning
                Write-Log -Message "Installing $Module module to current user Scope" -LogFileName $LogFileName -Severity Warning
                
                Install-Module -Name $Module -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
                $latestVersion = [Version](Get-Module -Name $Module).Version               
                Write-Log -Message "Importing module $Module with version $latestVersion" -LogFileName $LogFileName -Severity Information
                Import-Module -Name $Module -RequiredVersion $latestVersion -Force
            }
            else {
                #Admin, install to all users																		   
                Write-Log -Message "Installing the $Module module to all users" -LogFileName $LogFileName -Severity Warning
                Install-Module -Name $Module -Repository PSGallery -Force -AllowClobber
                $latestVersion = [Version](Get-Module -Name $Module).Version               
                Write-Log -Message "Importing module $Module with version $latestVersion" -LogFileName $LogFileName -Severity Information
                Import-Module -Name $Module -RequiredVersion $latestVersion -Force
            }
        }
        else {
            if ($UpdateAzModules) {
                Write-Log -Message "Checking updates for module $Module" -LogFileName $LogFileName -Severity Information
                $currentVersion = [Version](Get-InstalledModule | Where-Object {$_.Name -eq $Module}).Version
                # Get latest version from gallery
                $latestVersion = [Version](Find-Module -Name $Module).Version
                if ($currentVersion -ne $latestVersion) {
                    #check for Admin Privleges
                    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

                    if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                        #install to current user            
                        Write-Log -Message "Can not update the $Module module. You are not running as Administrator" -LogFileName $LogFileName -Severity Warning
                        Write-Log -Message "Updating $Module from [$currentVersion] to [$latestVersion] to current user Scope" -LogFileName $LogFileName -Severity Warning
                        Update-Module -Name $Module -RequiredVersion $latestVersion -Force
                    }
                    else {
                        #Admin - Install to all users																		   
                        Write-Log -Message "Updating $Module from [$currentVersion] to [$latestVersion] to all users" -LogFileName $LogFileName -Severity Warning
                        Update-Module -Name $Module -RequiredVersion $latestVersion -Force
                    }
                }
                else {
                    $latestVersion = [Version](Get-Module -Name $Module).Version               
                    Write-Log -Message "Importing module $Module with version $latestVersion" -LogFileName $LogFileName -Severity Information
                    Import-Module -Name $Module -RequiredVersion $latestVersion -Force
                }
            }
            else {
                $latestVersion = [Version](Get-Module -Name $Module).Version               
                Write-Log -Message "Importing module $Module with version $latestVersion" -LogFileName $LogFileName -Severity Information
                Import-Module -Name $Module -RequiredVersion $latestVersion -Force
            }
        }
        # Install-Module will obtain the module from the gallery and install it on your local machine, making it available for use.
        # Import-Module will bring the module and its functions into your current powershell session, if the module is installed.  
    }
    catch {
        Write-Log -Message "An error occurred in Get-RequiredModules() method - $($_)" -LogFileName $LogFileName -Severity Error        
    }
}

Function Clear-FileName {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )

    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
    $cleanName = [RegEx]::Replace($Name, "[$invalidChars]", [string]::Empty)
    return $cleanName
}

Function Download-SentinelArtifacts {
    param(
        [parameter(Mandatory = $true)] $SentinelWorkspaceArtifacts,
        [parameter(Mandatory = $true)] $ArtifactType,
        [parameter(Mandatory = $true)] $LogAnalyticsWorkspaceName
    )
    $TimeStamp = Get-Date -Format yyyyMMdd
    if ($SentinelWorkspaceArtifacts) {												  
		foreach ($WorkspaceArtifact in $SentinelWorkspaceArtifacts) {
			if (Test-Path "$FolderName/$LogAnalyticsWorkspaceName") {
				$WorkspaceDirectory = "$FolderName/$LogAnalyticsWorkspaceName"
			}
			else {
				$WorkspaceDirectory = New-Item -Path $FolderName -Name $LogAnalyticsWorkspaceName -ItemType "directory"
			}                                                           
			
			                              
            if (Test-Path "$WorkspaceDirectory/$ArtifactType") {
                $LocalArtifactsDirectory = "$WorkspaceDirectory/$ArtifactType"
            }
            else {
                $LocalArtifactsDirectory = New-Item -Path $WorkspaceDirectory -Name $ArtifactType -ItemType "directory"
            }  
            
	    $templateParameters = @{}

            $templateParameters.Add("workspace", @{                                        
                "type"= "String"
				"metadata"     = @{
                    "description" = "Log Analytics Workspace Name";
                }			   
            })

		$ArtifactDisplayName = $WorkspaceArtifact.properties.displayName
            if([string]::IsNullOrEmpty($ArtifactDisplayName)) {
                $ArtifactDisplayName = $WorkspaceArtifact.Id
            }		

            if($ArtifactType.Trim() -eq "AutomationRules") {
                $ArtifactProvider = "automationRules"
                $ArtifactKind = "AutomationRules"

                $templateParameters.Add("AutomationRuleDisplayName", @{                                        
                    "type"= "String"
                    "defaultValue" = "$ArtifactDisplayName"
                    "metadata"     = @{
                        "description" = "AutomationRuleDisplayName";
                    }
                })

                if ($WorkspaceArtifact.properties.triggeringLogic.conditions.Length -gt 0) {
                    $ConditionValues = $WorkspaceArtifact.properties.triggeringLogic.conditions
                    foreach ($PropertyVal in $ConditionValues) {  
                        $ConditionPropValues = $PropertyVal.conditionProperties.propertyValues
                        foreach ($PropVal in $ConditionPropValues) { 
                            if ($PropVal.Contains("alertRules")) {                   
                                $AssociatedAnalyticalRuleName = Split-Path $PropVal -leaf
                                $PropertyVal.conditionProperties.propertyValues = ""
                                $PropArrayVal = @()
                                $PropArrayVal += "[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers/', 'Microsoft.SecurityInsights'),'/alertRules/$($AssociatedAnalyticalRuleName.Trim())')]"
                                $PropertyVal.conditionProperties.propertyValues = $PropArrayVal
                            }
                        }
                    }
                }
                             
                if ($WorkspaceArtifact.properties.actions.Length -gt 0 ) {
                    $AutomationRuleActions = $WorkspaceArtifact.properties.actions
                    foreach($RuleAction in $AutomationRuleActions) {
                        if($RuleAction.actionType -ieq "RunPlaybook") {
                            $LogicAppResourceId = $RuleAction.actionConfiguration.logicAppResourceId
                            $RuleAction.actionConfiguration.logicAppResourceId = ""
                            if($RuleAction.actionConfiguration.tenantId) {
                                $RuleAction.actionConfiguration.tenantId = ""
                                $RuleAction.actionConfiguration.tenantId = "[subscription().tenantId]"
                            }
                            $LogicAppResourceId = Split-Path $LogicAppResourceId -leaf
                            $RuleAction.actionConfiguration.logicAppResourceId = "[concat(subscriptionResourceId('Microsoft.Resources/resourceGroups', resourceGroup().name), '/providers/Microsoft.Logic/workflows/', '$($LogicAppResourceId.Trim())')]"                            
                        }
                    }                   
                }    
                $WorkspaceArtifact.PSObject.Properties.Remove('etag')
                $WorkspaceArtifact.PSObject.Properties.Remove('id')
                $WorkspaceArtifact.properties.PSObject.Properties.Remove('lastModifiedTimeUtc')
                $WorkspaceArtifact.properties.PSObject.Properties.Remove('createdTimeUtc')
                $WorkspaceArtifact.properties.PSObject.Properties.Remove('lastModifiedBy')
                $WorkspaceArtifact.properties.PSObject.Properties.Remove('createdBy')

                $ArtifactName= $WorkspaceArtifact.name
                $WorkspaceArtifact.name = ""
                $WorkspaceArtifact.name = $($ArtifactName.Trim())
                $WorkspaceArtifact.type = ""
                $WorkspaceArtifact.type = "Microsoft.SecurityInsights/$ArtifactProvider"
                $WorkspaceArtifact | Add-Member -NotePropertyName "apiVersion" -NotePropertyValue "2019-01-01-preview" -Force
                $WorkspaceArtifact | Add-Member -NotePropertyName "scope" -NotePropertyValue "[concat('Microsoft.OperationalInsights/workspaces/', parameters('workspace'))]" -Force
                $WorkspaceArtifact.properties.displayName = ""
                $WorkspaceArtifact.properties.displayName = "[parameter('AutomationRuleDisplayName')]"
            }
            elseif ($ArtifactType.Trim() -eq "ScheduledAnalyticRules") {
                $ArtifactProvider = "alertRules"
                $ArtifactKind = "ScheduledAnalyticRules"
                $alertName = $WorkspaceArtifact.Name
                $WorkspaceArtifact.id = ""
                $WorkspaceArtifact.id = "[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', parameters('workspace'), 'Microsoft.SecurityInsights'),'/alertRules/$($alertName)')]"
                $WorkspaceArtifact | Add-Member -NotePropertyName "apiVersion" -NotePropertyValue "2021-09-01-preview" -Force
                $WorkspaceArtifact.PSObject.Properties.Remove('etag')
                $WorkspaceArtifact.properties.PSObject.Properties.Remove('lastModifiedUtc')
                
                $ArtifactName= $WorkspaceArtifact.name
                $WorkspaceArtifact.name = ""
                $WorkspaceArtifact.name = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/$($ArtifactName.Trim())')]"
                $WorkspaceArtifact.type = ""
                $WorkspaceArtifact.type = "Microsoft.OperationalInsights/workspaces/providers/$ArtifactProvider"                                
                 
            }
            elseif ($ArtifactType.Trim() -eq "Parsers") {
                $ArtifactProvider = "savedSearches"
                $ArtifactKind = "SavedSearches"
                $WorkspaceArtifact.PSObject.Properties.Remove('id')
                $WorkspaceArtifact | Add-Member -NotePropertyName "apiVersion" -NotePropertyValue "2020-08-01" -Force
                $WorkspaceArtifact.PSObject.Properties.Remove('etag')
                $WorkspaceArtifact.properties.PSObject.Properties.Remove('lastModifiedUtc')
                
                $ArtifactName= $WorkspaceArtifact.name
                $WorkspaceArtifact.name = ""
                $WorkspaceArtifact.name = "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/$($ArtifactName.Trim())')]"
                $WorkspaceArtifact.type = ""
                $WorkspaceArtifact.type = "Microsoft.OperationalInsights/workspaces/providers/$ArtifactProvider"                                
                 
            }
			elseif ($ArtifactType.Trim() -eq "Workbooks") {
                $ArtifactProvider = "workbooks"
                $ArtifactKind = "Workbooks"   
                $workbookId = New-Guid              
                
                #Add formattedTimeNow parameter since workbooks exist                
                $templateParameters.Add("formattedTimeNow", @{                                        
                    "type"= "String"
                    "defaultValue" = "[utcNow('g')]"
                    "metadata"     = @{
                        "description" = "Appended to workbook displayNames to make them unique";
                    }
                })

                $templateParameters.Add("workbook-id", @{                                        
                    "type"= "String"
                    "defaultValue" = "$workbookId"
                    "metadata"     = @{
                        "description" = "Unique id for the workbook";
                    }
                })

                $templateParameters.Add("workbook-name", @{                                        
                    "type"= "String"
                    "defaultValue" = "$ArtifactDisplayName"
                    "metadata"     = @{
                        "description" = "Name for the workbook";
                    }
                })
        
                # Create Workbook Resource Object
                $newWorkbook = [PSCustomObject]@{
                    type       = "Microsoft.Insights/workbooks";
                    name       = "[parameters('workbook-id')]";
                    location   = "[resourceGroup().location]";
                    kind       = "shared";
                    apiVersion = "2020-02-12";
                    properties = [PSCustomObject] @{
                        displayName    = "[concat(parameters('workbook-name'), ' - ', parameters('formattedTimeNow'))]";
                        serializedData = $WorkspaceArtifact.properties.serializedData;
                        version        = "1.0";
                        sourceId       = "[concat(resourceGroup().id, '/providers/Microsoft.OperationalInsights/workspaces/',parameters('workspace'))]";
                        category       = "sentinel"; 
                        etag           = "*"
                    }
                }

                $WorkspaceArtifact = $newWorkbook            
            }
                                           
            $armTemplate = [ordered] @{
                '$schema'= "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
                "contentVersion"= "1.0.0.0"
                "parameters"= $templateParameters                                        
                "resources"= @($WorkspaceArtifact)
            }                                 
                            
                   
															   
															
					   
            $armTemplateOutput = $armTemplate | ConvertTo-Json -Depth 100   
            $armTemplateOutput = $armTemplateOutput -replace "\\u0027", "'"    							
            Save-MicrosoftSentinelRule -Rule $armTemplateOutput -RuleName $ArtifactDisplayName -Format "Json" -Kind $ArtifactKind -Path $LocalArtifactsDirectory
                                
		}		
	}

}

#endregion

#region MainFunctions

Function FixJsonIndentation ($jsonOutput) {
    Try {
        $currentIndent = 0
        $tabSize = 4
        $lines = $jsonOutput.Split([Environment]::NewLine)
        $newString = ""
        foreach ($line in $lines)
        {
            # skip empty line
            if ($line.Trim() -eq "") {
                continue
            }

            # if the line with ], or }, reduce indent
            if ($line -match "[\]\}]+\,?\s*$") {
                $currentIndent -= 1
            }

            # add the line with the right indent
            if ($newString -eq "") {
                $newString = $line
            } else {
                $spaces = ""
                $matchFirstChar = [regex]::Match($line, '[^\s]+')
                
                $totalSpaces = $currentIndent * $tabSize
                if ($totalSpaces -gt 0) {
                    $spaces = " " * $totalSpaces
                }
                
                $newString += [Environment]::NewLine + $spaces + $line.Substring($matchFirstChar.Index)
            }

            # if the line with { or [ increase indent
            if ($line -match "[\[\{]+\s*$") {
                $currentIndent += 1
            }
        }
        return $newString
    }
    catch {
        Write-Log -Message "Error occured in FixJsonIndentation :$($_)" -LogFileName $LogFileName -Severity Error
    }
}
Function Save-MicrosoftSentinelRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]
        $Rule,
        [Parameter(Mandatory = $true)]
        [string]
        $RuleName,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Json", "Yaml")]
        [string]
        $Format,
        [Parameter(Mandatory = $true)]
        [ValidateSet("ScheduledAnalyticRules", "Hunting", "LiveStream", "AutomationRules", "SavedSearches", "Workbooks")]
        [string]
        $Kind,
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    if($null -ne $Rule) {        
        $Name = Clear-FileName -Name $RuleName
        $OutputPathFileName = Join-Path -Path $Path -ChildPath "$($Name).$($Kind.ToLowerInvariant()).rule.$($Format.ToLowerInvariant())"
        switch ($Format) {
            "Yaml" { 
                $Rule | ConvertTo-Yaml -OutFile $OutputPathFileName -Force
                }
            "Json" {
                FixJsonIndentation -jsonOutput $Rule | Set-Content $OutputPathFileName -Force
		git add --all $OutputPathFileName
		git commit -m "File added"
		git push
                Write-Log -Message "Successfully exported $Name" -LogFileName $LogFileName -Severity Information
                #$Rule | Out-File -FilePath $OutputPathFileName -Force 
            }
            Default {}
        }	
    }
    else {
        Write-Log -Message "$($_.Exception.Message)" -LogFileName $LogFileName -Severity Error
        throw
    }
}

Function Get-MicrosoftSentinelAlertRule {
    [cmdletbinding()]
    param (        
        [Parameter(Mandatory)]        
        [string]$BaseUri,
        
        [Parameter(Mandatory = $false)]        
        [string[]]$RuleName,

        [Parameter(Mandatory = $false)]        
        [Kind[]]$Kind,

        [Parameter(Mandatory = $false)]        
        [DateTime]$LastModified,

        [Parameter(Mandatory = $false)]        
        [switch]$SkipPlaybook
    )
      
    $BaseUri = $ResourceManagerUrl.TrimEnd('/')+$BaseUri
    $uri = "$BaseUri/providers/Microsoft.SecurityInsights/alertRules?api-version=2021-09-01-preview"
    Write-Log -Message "End point $uri" -LogFileName $LogFileName -Severity Information
    

    try {
        $alertRules = Invoke-RestMethod -Uri $uri -Method Get -Headers $APIHeaders
    }
    catch {
        Write-Log $_ -LogFileName $LogFileName -Severity Error            
        Write-Log -Message "Unable to get alert rules with error code: $($_.Exception.Message)" -LogFileName $LogFileName -Severity Error
    }
    
    if ($alertRules.value -and $LastModified) {
        Write-Log -Message "Filtering for rules modified after $LastModified" -LogFileName $LogFileName -Severity Error        
        $alertRules.value = $alertRules.value | Where-Object { $_.properties.lastModifiedUtc -gt $LastModified }
    }
    if ($alertRules.value) {
        Write-Log -Message "Found $($alertRules.value.count) Alert rules" -LogFileName $LogFileName -Severity Information
        Write-Verbose "Found $($alertRules.value.count) Alert rules"
        return $alertRules.value        
    }
    else {
        Write-Log -Message "No Rules found on $BaseUri" -LogFileName $LogFileName -Severity Information
    }
    
}

Function Get-MicrosoftSentinelWorkbooks {
[cmdletbinding()]
    param (
        [Parameter(Mandatory)]
        [string]$BaseUri
    )
    
    $BaseUri = "https://management.azure.com/subscriptions/" + $SubscriptionID + "/resourcegroups/" +$ResourceGroupName
    $uri = "$BaseUri/providers/microsoft.insights/workbooks?api-version=2022-04-01&category=sentinel&canfetchcontent=true"

    Write-Log -Message "End point $uri" -LogFileName $LogFileName -Severity Information
    try {
        $Workbooks = Invoke-RestMethod -Uri $uri -Method GET -Headers $APIHeaders
    }
    catch {
        Write-Log -Message $_ -LogFileName $LogFileName -Severity Error
        Write-Log -Message "Unable to get workbooks with error code: $($_.Exception.Message)" -LogFileName $LogFileName -Severity Error
    }
    if ($Workbooks.value) {
        Write-Log -Message "Found $($Workbooks.value.count) Workbooks" -LogFileName $LogFileName -Severity Information
        return $Workbooks.value
    }
    else {
        Write-Log -Message "No Workbooks found on $BaseUri" -LogFileName $LogFileName -Severity Information
    }
    return $Workbooks.value
}

Function Get-MicrosoftSentinelAutomationRule {   
    [cmdletbinding()]
    param (        
        [Parameter(Mandatory)]        
        [string]$BaseUri      
    )
      
    $BaseUri = $ResourceManagerUrl.TrimEnd('/')+$BaseUri
    $uri = "$BaseUri/providers/Microsoft.SecurityInsights/automationRules?api-version=2021-09-01-preview"
    Write-Log -Message "End point $uri" -LogFileName $LogFileName -Severity Information
    

    try {
        $automationRules = Invoke-RestMethod -Uri $uri -Method Get -Headers $APIHeaders
    }
    catch {
        Write-Log $_ -LogFileName $LogFileName -Severity Error            
        Write-Log -Message "Unable to get automation rules with error code: $($_.Exception.Message)" -LogFileName $LogFileName -Severity Error
    }
    
    if ($automationRules.value -and $LastModified) {
        Write-Log -Message "Filtering for rules modified after $LastModified" -LogFileName $LogFileName -Severity Error        
        $automationRules.value = $automationRules.value | Where-Object { $_.properties.lastModifiedUtc -gt $LastModified }
    }
    if ($automationRules.value) {
        Write-Log -Message "Found $($automationRules.value.count) Automation rules" -LogFileName $LogFileName -Severity Information        
        return $automationRules.value        
    }
    else {
        Write-Log -Message "No AutomationRules found on $BaseUri" -LogFileName $LogFileName -Severity Information
    }
    
}

Function Get-MicrosoftSentinelParsers {   
    [cmdletbinding()]
    param (        
        [Parameter(Mandatory)]        
        [string]$BaseUri,

        [Parameter(Mandatory)]        
        [string]$LogAnalyticsWorkspaceName
        
        
    )
      
    $BaseUri = $ResourceManagerUrl.TrimEnd('/')+$BaseUri    
    $uri = "$BaseUri/savedSearches?api-version=2020-08-01"
    Write-Log -Message "End point $uri" -LogFileName $LogFileName -Severity Information
    

    try {
        $Parsers = Invoke-RestMethod -Uri $uri -Method GET -Headers $APIHeaders
    }
    catch {
        Write-Log -Message $_ -LogFileName $LogFileName -Severity Error            
        Write-Log -Message "Unable to get parsers with error code: $($_.Exception.Message)" -LogFileName $LogFileName -Severity Error
    }  

    return $Parsers.value
}
#endregion MainFunctions

# Installing the required module
$UpdateAzModules = $false
Get-RequiredModules("Az.Accounts")
Get-RequiredModules("Az.OperationalInsights")


$TimeStamp = Get-Date -Format yyyyMMdd_HHmmss 
$LogFileName = '{0}_{1}.csv' -f "Export_Microsoft_Sentinel_Rules", $TimeStamp

# Check Powershell version, needs to be 5 or higher
if ($host.Version.Major -lt 5) {
    Write-Log -Message "Supported PowerShell version for this script is 7" -LogFileName $LogFileName -Severity Error    
    exit
}

#disconnect exiting connections and clearing contexts.
Write-Log -Message "Clearing existing Azure connection" -LogFileName $LogFileName -Severity Information
    
$null = Disconnect-AzAccount -ContextName 'MyAzContext' -ErrorAction SilentlyContinue
    
Write-Log -Message "Clearing existing Azure context `n" -LogFileName $LogFileName -Severity Information
    
get-azcontext -ListAvailable | ForEach-Object{$_ | remove-azcontext -Force -Verbose | Out-Null} #remove all connected content
    
Write-Log -Message "Clearing of existing connection and context completed." -LogFileName $LogFileName -Severity Information
Try {
    #Connect to tenant with context name and save it to variable
    #Connect-AzAccount -Tenant $TenantID -ContextName 'MyAzContext' -Force -ErrorAction Stop
	
	#Login-ServicePrincipal
	$pass = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
	$cred = New-Object -TypeName pscredential -ArgumentList $ClientID, $pass

	Connect-AzAccount -Subscription $SubscriptionID -ServicePrincipal -Credential $cred -Tenant $TenantID -ErrorAction Stop
        
    #Select subscription to build
    #$GetSubscriptions = Get-AzSubscription -TenantId $TenantID | Where-Object {($_.state -eq 'enabled') } | Out-GridView -Title "Select Subscription to Use" -PassThru       
}
catch {    
    Write-Log -Message "Error When trying to connect to tenant : $($_)" -LogFileName $LogFileName -Severity Error
    Invoke-WebRequest -UseBasicParsing $NotificationURL -ContentType "application/json" -Method POST -Body "{ 'msg':'Sentinel backup have some error. Please check'}"
    exit 1   
}

#loop through each selected subscription.. 
Try 
{
        #Set context for subscription being built
        $azContext = Set-AzContext -Subscription $SubscriptionID

        Write-Log -Message "Working in Subscription: $($SubscriptionID)" -LogFileName $LogFileName -Severity Information

        $LAW = Get-AzOperationalInsightsWorkspace | Where-Object { $_.ProvisioningState -eq "Succeeded" -and $_.Name -eq "$SentinelWorkspaceName"} | Select-Object -Property Name, ResourceGroupName, Location, ResourceId 
		
        if($null -eq $LAW) {
            Write-Log -Message "No Log Analytics workspace found..." -LogFileName $LogFileName -Severity Error
	    exit 1
        }
        else {
            Write-Log -Message "Listing Log Analytics workspace" -LogFileName $LogFileName -Severity Information                    
            
            
        $AzureAccessToken = (Get-AzAccessToken).Token
        $ResourceManagerUrl = $azContext.Environment.ResourceManagerUrl        
        $APIHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $APIHeaders.Add("Content-Type", "application/json")
        $APIHeaders.Add("Authorization", "Bearer $AzureAccessToken")      
        $ResourceGroupName = $LAW.ResourceGroupName
        

        $SentinelArtifacts = New-Object -TypeName System.Collections.ArrayList
        $SentinelArtifacts.Add("ScheduledAnalyticRules")
        $SentinelArtifacts.Add("AutomationRules")
        $SentinelArtifacts.Add("Parsers")     
        $SentinelArtifacts.Add("Workbooks")	
        
	$ArtifactsToDownload = $SentinelArtifacts                
       
	$FolderName = "$PSScriptRoot\$BackupFolderName"
	
	if (Test-Path $FolderName\Sentinel) {	
		rm -r $FolderName\Sentinel
		git add --all
		git commit -m "Delete folder sentinel"
		git push origin main
	}
	
        if (Test-Path $FolderName) {
             Write-Log -Message "$FolderName Path Exists" -LogFileName $LogFileName -Severity Information
        }
        else {
			  try {
                   $null = New-Item -Path $FolderName -Force -ItemType Directory -ErrorAction Stop
              }
              catch {
					$ErrorMessage = $_.Exception.Message
					Write-Log -Message $ErrorMessage -LogFileName $LogFileName -Severity Error					
					Break
              }
        }

        foreach($ArtifactToDownload in $ArtifactsToDownload) {
		if($ArtifactToDownload.Trim() -eq "AutomationRules") {
			try {
				$AutomationRules = Get-MicrosoftSentinelAutomationRule -BaseUri $LAW.ResourceId.ToString()
			}
			catch {
				$ErrorMessage = $_.Exception.Message
				Write-Log $ErrorMessage -LogFileName $LogFileName -Severity Error
				Write-Log $_ -LogFileName $LogFileName -Severity Error
				exit 1
			}
			if ($null -ne $AutomationRules) {
				Download-SentinelArtifacts -SentinelWorkspaceArtifacts $AutomationRules -ArtifactType $ArtifactToDownload.Trim() -LogAnalyticsWorkspaceName Sentinel
			}
		}
		elseif ($ArtifactToDownload.Trim() -eq "ScheduledAnalyticRules") {
			try {
				$AnalyticalRules = Get-MicrosoftSentinelAlertRule -BaseUri $LAW.ResourceId.ToString()
			}
			catch {
				$ErrorMessage = $_.Exception.Message
				Write-Log $ErrorMessage -LogFileName $LogFileName -Severity Error
				Write-Log $_ -LogFileName $LogFileName -Severity Error 
				exit 1
			}
			$ScheduledAnalyticalRules = New-Object -TypeName System.Collections.ArrayList
			foreach($AnalyticalRule in $AnalyticalRules) {
				if($AnalyticalRule.kind -eq "Scheduled") {
					$ScheduledAnalyticalRules.Add($AnalyticalRule)
				}
			}
			if ($null -ne $AnalyticalRules) {
				Download-SentinelArtifacts -SentinelWorkspaceArtifacts $ScheduledAnalyticalRules -ArtifactType $ArtifactToDownload.Trim() -LogAnalyticsWorkspaceName Sentinel                    
			}
		}
		elseif($ArtifactToDownload.Trim() -eq "Parsers") {
			try {
				$SavedSearches = Get-MicrosoftSentinelParsers -BaseUri $($LAW.ResourceId.ToString()) -LogAnalyticsWorkspaceName Sentinel
			}
			catch {
				$ErrorMessage = $_.Exception.Message
				Write-Log $ErrorMessage -LogFileName $LogFileName -Severity Error
				Write-Log $_ -LogFileName $LogFileName -Severity Error
				exit 1
			}
			if ($null -ne $SavedSearches) {
				Download-SentinelArtifacts -SentinelWorkspaceArtifacts $SavedSearches -ArtifactType $ArtifactToDownload.Trim() -LogAnalyticsWorkspaceName Sentinel
			}
		}
		elseif($ArtifactToDownload.Trim() -eq "Workbooks") {
			try {
				$Workbooks = Get-MicrosoftSentinelWorkbooks -BaseUri $($LAW.ResourceId.ToString())
			}
			catch {
				$ErrorMessage = $_.Exception.Message
				Write-Log $ErrorMessage -LogFileName $LogFileName -Severity Error
				Write-Log $_ -LogFileName $LogFileName -Severity Error
				exit 1
			}
			if ($null -ne $Workbooks) {
				Download-SentinelArtifacts -SentinelWorkspaceArtifacts $Workbooks -ArtifactType $ArtifactToDownload.Trim() -LogAnalyticsWorkspaceName Sentinel
			}
		}
	}     
    } 	
}
catch [Exception] {
	$ErrorMessage = $_.Exception.Message 
	Write-Log $ErrorMessage -LogFileName $LogFileName -Severity Error
	exit 1
}		 

#endregion DriverProgram 
