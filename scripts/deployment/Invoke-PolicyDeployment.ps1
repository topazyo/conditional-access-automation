param (
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$true)]
    [string]$ConfigPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Import required modules
Import-Module "./src/modules/policy-management/PolicyManager.ps1"

# Initialize logging
$logPath = "./logs/deployment_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $logPath

try {
    # --- 1. Validate ConfigPath ---
    Write-Host "Validating configuration file path: $ConfigPath"
    if (-not (Test-Path -Path $ConfigPath -PathType Leaf)) {
        throw "Configuration file not found at path: $ConfigPath"
    }
    if ($ConfigPath -notmatch '\.json$') { # Using -notmatch for case-insensitivity
        throw "Configuration file must be a .json file. Provided: $ConfigPath"
    }
    Write-Host "Configuration file path seems valid."

    # Load configuration
    $configContent = Get-Content $ConfigPath -ErrorAction Stop
    $config = $configContent | ConvertFrom-Json -ErrorAction Stop # Stop if JSON parsing fails

    # --- 2. Validate $config object and 'policies' property ---
    Write-Host "Validating structure of configuration file content..."
    if ($null -eq $config) {
        throw "Failed to parse JSON from configuration file, or file is empty."
    }
    if ($null -eq $config.PSObject.Properties['policies']) { # Check if 'policies' property exists
        throw "Configuration file must contain a 'policies' array/property at the root level."
    }
    if ($config.policies -isnot [array]) {
        throw "'policies' property in configuration file must be an array."
    }
    if ($config.policies.Count -eq 0) {
        Write-Warning "No policies found in the configuration file's 'policies' array. Nothing to deploy."
        # Script will gracefully exit the loop below.
    } else {
        Write-Host "$($config.policies.Count) policies found in configuration."
    }

    # Initialize policy manager
    $policyManager = [ConditionalAccessPolicyManager]::new($TenantId)
    
    # Deploy policies
    $requiredPolicyKeys = @('DisplayName', 'State', 'Conditions', 'GrantControls')

    foreach ($policyEntry in $config.policies) {
        # --- 3. Validate individual policy entry ---
        if ($null -eq $policyEntry) {
            Write-Warning "Skipping null policy entry in configuration's 'policies' array."
            continue
        }
        if ($policyEntry -isnot [hashtable] -and $policyEntry -isnot [pscustomobject]) {
            Write-Warning "Skipping invalid policy entry (not a hashtable/object): '$($policyEntry.ToString())'" # Use .ToString() in case it's a weird type
            continue
        }

        # Check for essential top-level properties
        $missingKeys = $false
        foreach ($key in $requiredPolicyKeys) {
            if (-not $policyEntry.PSObject.Properties.ContainsKey($key)) {
                $policyDisplayNameForError = if ($policyEntry.PSObject.Properties.ContainsKey('DisplayName')) { $policyEntry.DisplayName } else { "Unnamed Policy" }
                Write-Warning "Skipping policy '$policyDisplayNameForError' due to missing required top-level property: '$key'."
                $missingKeys = $true
                break # Stop checking keys for this policy
            }
        }
        if ($missingKeys) {
            continue # Move to the next policy entry
        }

        # Optional deeper checks for Conditions and GrantControls being hashtables
        if ($policyEntry.Conditions -isnot [hashtable] -and $policyEntry.Conditions -isnot [pscustomobject]) {
            Write-Warning "Skipping policy '$($policyEntry.DisplayName)' because 'Conditions' property is not a valid object/hashtable."
            continue
        }
        if ($policyEntry.GrantControls -isnot [hashtable] -and $policyEntry.GrantControls -isnot [pscustomobject]) {
            Write-Warning "Skipping policy '$($policyEntry.DisplayName)' because 'GrantControls' property is not a valid object/hashtable."
            continue
        }

        Write-Host "Processing policy for deployment: $($policyEntry.DisplayName)"
        
        if (-not $WhatIf) {
            Write-Host "Attempting to deploy policy: $($policyEntry.DisplayName)..."
            $policyManager.DeployPolicy($policyEntry) # DeployPolicy itself has try-catch and validation
            Write-Host "Deployment call completed for: $($policyEntry.DisplayName)."
        }
        else {
            Write-Host "WhatIf: Would deploy policy '$($policyEntry.DisplayName)' with details: $($policyEntry | ConvertTo-Json -Depth 3 -Compress)"
        }
    }
    Write-Host "All policies in configuration processed."
}
catch {
    # Catch specific exceptions if needed, or handle general errors
    Write-Error "Deployment script failed with an error: $($_.Exception.Message)"
    Write-Error "ScriptStackTrace: $($_.ScriptStackTrace)"
    # Re-throw to ensure script signals failure, unless specific recovery is intended
    throw
}
finally {
    Stop-Transcript
}