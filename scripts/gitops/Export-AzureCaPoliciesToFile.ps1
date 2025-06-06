<#
.SYNOPSIS
    Exports all Azure Conditional Access policies from a tenant to individual JSON files.

.DESCRIPTION
    This script connects to Microsoft Graph, retrieves all Conditional Access policies,
    and exports each policy as a separate JSON file into the specified output directory.
    File names are generated from the policy's display name and ID.

.PARAMETER OutputDirectory
    The directory where the JSON files for the policies will be saved.
    This parameter is mandatory.

.PARAMETER TenantId
    Optional. The Tenant ID to connect to. If not provided, Connect-MgGraph
    will attempt to connect using existing credentials or prompt for interactive login.

.EXAMPLE
    PS> ./Export-AzureCaPoliciesToFile.ps1 -OutputDirectory ./CaPoliciesOutput
    Exports all policies to the './CaPoliciesOutput' directory in the current location.

.EXAMPLE
    PS> ./Export-AzureCaPoliciesToFile.ps1 -OutputDirectory C:\Exports\CaPolicies -TenantId "your-tenant-id.onmicrosoft.com"
    Exports all policies from the specified tenant to 'C:\Exports\CaPolicies'.
#>
param (
    [Parameter(Mandatory=$true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory=$false)]
    [string]$TenantId
)

# Function to sanitize a string for use as a filename
function Sanitize-FileName([string]$name) {
    # Replace common invalid file name characters with an underscore
    # Also remove leading/trailing whitespace and replace multiple underscores with a single one
    $sanitized = $name -replace '[\/:*?"<>|]', '_' -replace '\s+', ' ' -replace '_{2,}', '_' | ForEach-Object { $_.Trim() }
    # Limit length if necessary (Windows max path component is 255)
    if ($sanitized.Length -gt 200) { # Leave some room for ID and extension
        $sanitized = $sanitized.Substring(0, 200)
    }
    return $sanitized
}

try {
    Write-Host "Starting Conditional Access policy export process..."

    # Import necessary module
    Write-Verbose "Importing Microsoft.Graph.Identity.SignIns module..."
    Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop

    # Connect to Microsoft Graph
    Write-Verbose "Attempting to connect to Microsoft Graph..."
    if (-not [string]::IsNullOrEmpty($TenantId)) {
        Connect-MgGraph -TenantId $TenantId -ErrorAction Stop
    } else {
        Connect-MgGraph -ErrorAction Stop # Assumes existing connection or prompts interactively
    }
    Write-Host "Successfully connected to Microsoft Graph."

    # Retrieve all Conditional Access policies
    Write-Verbose "Retrieving all Conditional Access policies..."
    $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop

    if ($null -eq $policies -or $policies.Count -eq 0) {
        Write-Host "No Conditional Access policies found in the tenant, or unable to retrieve them."
        # Exit gracefully if running as a script, or just return if part of a larger flow
        if ($MyInvocation.MyCommand.CommandType -eq 'ExternalScript') { exit 0 } else { return }
    }
    Write-Host "Found $($policies.Count) policies."

    # Create the output directory if it doesn't exist
    if (-not (Test-Path -Path $OutputDirectory -PathType Container)) {
        Write-Verbose "Output directory '$OutputDirectory' does not exist. Creating it..."
        New-Item -ItemType Directory -Path $OutputDirectory -Force -ErrorAction Stop | Out-Null
        Write-Host "Output directory '$OutputDirectory' created."
    } else {
        Write-Verbose "Output directory '$OutputDirectory' already exists."
    }

    # Iterate through each policy and export it
    Write-Host "Exporting policies..."
    foreach ($policy in $policies) {
        $policyDisplayName = $policy.DisplayName
        $policyId = $policy.Id
        Write-Verbose "Processing policy '$policyDisplayName' (Id: $policyId)..."

        $sanitizedDisplayName = Sanitize-FileName -name $policyDisplayName
        $fileName = "$($sanitizedDisplayName) ($($policyId)).json"
        $filePath = Join-Path -Path $OutputDirectory -ChildPath $fileName

        try {
            # Convert the policy object to a formatted JSON string
            # Note: The $policy object from Get-MgIdentityConditionalAccessPolicy is a complex object.
            # ConvertTo-Json needs sufficient depth. The object often contains circular references
            # or very deep structures that ConvertTo-Json can struggle with or produce overly verbose output.
            # For CA policies, often selecting specific properties before conversion is more robust if the raw object fails.
            # However, for backup/GitOps, capturing as much as possible is desired.
            # A depth of 10 is usually good for Graph objects.
            # Using -Compress to reduce file size slightly, but -Indent for readability if preferred.
            # Let's use -Indent for better human readability in GitOps.
            $policyJson = $policy | ConvertTo-Json -Depth 10 -EnumsAsStrings # -Indent available in PS 7+ for pretty print
                                                                           # For PS 5.1, -Indent is not an option, output will be compact.
                                                                           # If PS 7+ is guaranteed, add -Indent. Assuming generic for now.

            # For PowerShell 7+, ConvertTo-Json has -Indent
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                 $policyJson = $policy | ConvertTo-Json -Depth 10 -EnumsAsStrings -Indent
            }


            $policyJson | Out-File -FilePath $filePath -Encoding UTF8 -ErrorAction Stop
            Write-Verbose "Successfully exported policy '$policyDisplayName' to '$filePath'"
        }
        catch {
            Write-Error "Failed to export policy '$policyDisplayName' (Id: $policyId) to '$filePath'. Error: $($_.Exception.Message)"
            # Continue to next policy
        }
    }

    Write-Host "Successfully exported $($policies.Count) policies to '$OutputDirectory'."
}
catch {
    Write-Error "An error occurred during the policy export process: $($_.Exception.Message)"
    Write-Error "ScriptStackTrace: $($_.ScriptStackTrace)"
    if ($MyInvocation.MyCommand.CommandType -eq 'ExternalScript') { exit 1 } else { throw }
}
finally {
    # No explicit Disconnect-MgGraph needed unless specific session management is required.
    Write-Host "Policy export process finished."
}
