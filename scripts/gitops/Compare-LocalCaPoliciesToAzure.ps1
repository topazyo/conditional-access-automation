<#
.SYNOPSIS
    Compares local Conditional Access policy JSON files with policies in Azure AD.

.DESCRIPTION
    This script connects to Microsoft Graph, retrieves all Conditional Access policies from Azure AD,
    and compares them against a directory of local policy JSON files.
    It reports on policies that are new in Azure, new locally (not in Azure), modified, or unchanged.

.PARAMETER LocalDirectory
    The directory containing the local policy JSON files to compare.
    This parameter is mandatory.

.PARAMETER TenantId
    Optional. The Tenant ID to connect to. If not provided, Connect-MgGraph
    will attempt to connect using existing credentials or prompt for interactive login.

.EXAMPLE
    PS> ./Compare-LocalCaPoliciesToAzure.ps1 -LocalDirectory ./CaPoliciesBackup
    Compares policies in './CaPoliciesBackup' with Azure AD.

.EXAMPLE
    PS> ./Compare-LocalCaPoliciesToAzure.ps1 -LocalDirectory C:\Exports\CaPolicies -TenantId "your-tenant-id.onmicrosoft.com"
    Compares policies from 'C:\Exports\CaPolicies' with the specified Azure AD tenant.
#>
param (
    [Parameter(Mandatory=$true)]
    [string]$LocalDirectory,

    [Parameter(Mandatory=$false)]
    [string]$TenantId
)

function ConvertTo-ComparableJson([object]$policyObject) {
    # Select only the properties that typically define a policy's desired state.
    # Exclude read-only or operational data that might differ between local definition and Azure state.
    # Order of properties in Select-Object and sorting keys in sub-hashtables can affect JSON string if not careful.
    # For consistent comparison, ConvertTo-Json with -Compress helps, but true canonical JSON is hard in PS.
    # This selection aims to capture the core configurable aspects.

    $comparableObject = @{
        displayName = $policyObject.DisplayName
        state = $policyObject.State
        conditions = $policyObject.Conditions # Assuming this is already a well-structured hashtable/pscustomobject
        grantControls = $policyObject.GrantControls # Assuming this is already a well-structured hashtable/pscustomobject
        sessionControls = $policyObject.SessionControls # Assuming this is already a well-structured hashtable/pscustomobject
    }
    # GrantControls and SessionControls can sometimes be $null
    if ($null -eq $policyObject.GrantControls) { $comparableObject.Remove("grantControls") }
    if ($null -eq $policyObject.SessionControls) { $comparableObject.Remove("sessionControls") }

    return $comparableObject | ConvertTo-Json -Depth 10 -Compress -EnumsAsStrings
}

try {
    Write-Host "Starting Conditional Access policy comparison..." -ForegroundColor Yellow

    # Import necessary module
    Write-Verbose "Importing Microsoft.Graph.Identity.SignIns module..."
    Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop

    # Connect to Microsoft Graph
    Write-Verbose "Attempting to connect to Microsoft Graph..."
    if (-not [string]::IsNullOrEmpty($TenantId)) {
        Connect-MgGraph -TenantId $TenantId -ErrorAction Stop
    } else {
        Connect-MgGraph -ErrorAction Stop
    }
    Write-Host "Successfully connected to Microsoft Graph."

    # --- 1. Load Local Policies ---
    Write-Verbose "Loading local policies from directory: $LocalDirectory"
    if (-not (Test-Path -Path $LocalDirectory -PathType Container)) {
        throw "Local policy directory not found: $LocalDirectory"
    }
    $localPolicyFiles = Get-ChildItem -Path $LocalDirectory -Filter "*.json" -ErrorAction SilentlyContinue
    $localPoliciesMap = @{}

    if ($localPolicyFiles.Count -eq 0) {
        Write-Warning "No JSON files found in local directory: $LocalDirectory"
    } else {
        Write-Host "Found $($localPolicyFiles.Count) local JSON files. Attempting to parse..."
        foreach ($file in $localPolicyFiles) {
            Write-Verbose "Processing local file: $($file.FullName)"
            $policyContent = $null
            try {
                $policyContent = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                Write-Warning "Could not parse JSON from file: $($file.FullName). Error: $($_.Exception.Message). Skipping."
                continue
            }

            if ($null -eq $policyContent) { # Should be caught by try-catch if ConvertFrom-Json fails
                Write-Warning "Parsed content is null for file: $($file.FullName). Skipping."
                continue
            }

            if ($policyContent.PSObject.Properties['id'] -and -not [string]::IsNullOrEmpty($policyContent.id)) {
                $localPoliciesMap[$policyContent.id] = $policyContent
                Write-Verbose "Loaded local policy '$($policyContent.displayName)' (Id: $($policyContent.id))"
            } else {
                Write-Warning "Policy file $($file.FullName) does not contain a valid 'id' property or it is empty. Skipping."
            }
        }
        Write-Host "Successfully loaded $($localPoliciesMap.Keys.Count) policies from local files."
    }


    # --- 2. Fetch Azure Policies ---
    Write-Verbose "Retrieving all Conditional Access policies from Azure AD..."
    $azurePoliciesList = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue

    if ($null -eq $azurePoliciesList) { # Get-Mg* typically returns $null on error even with SilentlyContinue if it can't make the call
        Write-Error "Failed to retrieve policies from Azure AD. Ensure connection is valid and permissions are sufficient."
        if ($MyInvocation.MyCommand.CommandType -eq 'ExternalScript') { exit 1 } else { throw }
    }

    $azurePoliciesMap = @{}
    foreach ($policy in $azurePoliciesList) {
        $azurePoliciesMap[$policy.Id] = $policy
    }
    Write-Host "Found $($azurePoliciesMap.Keys.Count) policies in Azure AD."

    # --- 3. Compare Policies ---
    Write-Verbose "Comparing local policies with Azure AD policies..."
    $newInAzure = [System.Collections.Generic.List[object]]::new()
    $newLocally = [System.Collections.Generic.List[object]]::new() # Policies in local files but not in Azure (potentially to be created)
    $modifiedInAzure = [System.Collections.Generic.List[object]]::new() # Exists in both, but content differs
    $unchanged = [System.Collections.Generic.List[object]]::new()

    # Check policies present in Azure against local files
    foreach ($azureId in $azurePoliciesMap.Keys) {
        $azurePolicy = $azurePoliciesMap[$azureId]
        if (-not $localPoliciesMap.ContainsKey($azureId)) {
            $newInAzure.Add([pscustomobject]@{ Name = $azurePolicy.DisplayName; Id = $azureId })
        } else {
            # Exists in both, now compare content
            $localPolicy = $localPoliciesMap[$azureId]

            $localPolicyJsonForCompare = ConvertTo-ComparableJson -policyObject $localPolicy
            $azurePolicyJsonForCompare = ConvertTo-ComparableJson -policyObject $azurePolicy

            if ($localPolicyJsonForCompare -ne $azurePolicyJsonForCompare) {
                # For more detailed diff:
                # $diff = Compare-Object -ReferenceObject $localPolicy -DifferenceObject $azurePolicy -Property DisplayName, State # etc.
                # For now, just flag as modified with basic state info.
                $modifiedInAzure.Add([pscustomobject]@{
                    Name = $azurePolicy.DisplayName # Use Azure's name as source of truth for display
                    Id = $azureId
                    LocalDisplayName = $localPolicy.DisplayName
                    AzureDisplayName = $azurePolicy.DisplayName
                    LocalState = $localPolicy.State
                    AzureState = $azurePolicy.State
                    # Note: Could add more detailed diff info here if needed
                })
            } else {
                $unchanged.Add([pscustomobject]@{ Name = $azurePolicy.DisplayName; Id = $azureId })
            }
        }
    }

    # Check for policies present locally but not in Azure
    foreach ($localId in $localPoliciesMap.Keys) {
        if (-not $azurePoliciesMap.ContainsKey($localId)) {
            $localPolicy = $localPoliciesMap[$localId]
            $newLocally.Add([pscustomobject]@{ Name = $localPolicy.DisplayName; Id = $localId; State = $localPolicy.State })
        }
    }

    # --- 4. Output Report ---
    Write-Host "`n" + ("-"*30) + " Comparison Report " + ("-"*30) -ForegroundColor Green

    Write-Host "`nPolicies only in Azure (potentially new or not tracked locally): $($newInAzure.Count)" -ForegroundColor Cyan
    $newInAzure | ForEach-Object { Write-Host "  - Name: '$($_.Name)', ID: $($_.Id)" }

    Write-Host "`nPolicies only in local files (potentially pending creation in Azure or orphaned): $($newLocally.Count)" -ForegroundColor Cyan
    $newLocally | ForEach-Object { Write-Host "  - Name: '$($_.Name)', ID: $($_.Id), State: $($_.State)" }

    Write-Host "`nPolicies modified (different in Azure compared to local file): $($modifiedInAzure.Count)" -ForegroundColor Yellow
    $modifiedInAzure | ForEach-Object {
        Write-Host "  - Name (Azure): '$($_.AzureDisplayName)', ID: $($_.Id)"
        if ($_.LocalDisplayName -ne $_.AzureDisplayName) { Write-Host "    (Local Name: '$($_.LocalDisplayName)')" }
        if ($_.LocalState -ne $_.AzureState) { Write-Host "    States Differ -> Local: '$($_.LocalState)', Azure: '$($_.AzureState)'" }
        else { Write-Host "    State: '$($_.AzureState)' (content differs in other properties like conditions/grants)"}
    }

    Write-Host "`nPolicies unchanged (found in both local files and Azure with no detected differences): $($unchanged.Count)" -ForegroundColor Green
    # $unchanged | ForEach-Object { Write-Host "  - Name: '$($_.Name)', ID: $($_.Id)" } # Optional: list unchanged

    Write-Host "`n" + ("-"*79)
    Write-Host "Comparison finished."

}
catch {
    Write-Error "An error occurred during the policy comparison process: $($_.Exception.Message)"
    Write-Error "ScriptStackTrace: $($_.ScriptStackTrace)"
    if ($MyInvocation.MyCommand.CommandType -eq 'ExternalScript') { exit 1 } else { throw }
}
finally {
    Write-Host "Policy comparison script execution completed."
}
