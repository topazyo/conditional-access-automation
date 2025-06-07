# scripts/tools/invoke_policy_simulation.ps1
# Script to perform a simplified, local "What If" simulation for a CA policy definition.
# DISCLAIMER: This is a conceptual tool and NOT a replacement for Azure AD's "What If" functionality.
# It provides a local evaluation based on provided inputs and existing policy comparison.

param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Leaf -ErrorAction Stop})] # Added ValidateScript
    [string]$PolicyDefinitionPath,

    [Parameter(Mandatory=$true)]
    [string]$SimUserPrincipalName,

    [Parameter(Mandatory=$false)]
    [string]$SimUserLocationId,

    [Parameter(Mandatory=$false)]
    [string]$SimUserDevicePlatform,

    [Parameter(Mandatory=$false)]
    [string]$SimUserDeviceState,

    [Parameter(Mandatory=$true)]
    [string]$SimApplicationId,

    [Parameter(Mandatory=$false)]
    [ValidateSet('low', 'medium', 'high', IgnoreCase = $true)] # Added ValidateSet for risk levels
    [string]$SimSignInRiskLevel,

    [Parameter(Mandatory=$false)]
    [ValidateSet('low', 'medium', 'high', IgnoreCase = $true)]
    [string]$SimUserRiskLevel
)

# --- HELPER FUNCTIONS ---
function Test-UserConditionMatch {
    param(
        [Parameter(Mandatory=$true)]
        [object]$userConditions, # Expects $PolicyToSimulate.Conditions.Users object
        [Parameter(Mandatory=$true)]
        [string]$simUserUPN
    )

    if ($null -eq $userConditions) {
        Write-Verbose "User condition in policy is null, considered a match for this aspect."
        return $true # No user condition specified in policy means it applies to users from this perspective
    }

    $includeUsers = @($userConditions.IncludeUsers)
    $excludeUsers = @($userConditions.ExcludeUsers)
    # Groups and Roles are not evaluated in this simplified version
    # GuestsOrExternalUsers are not evaluated in this simplified version

    if (($excludeUsers -contains $simUserUPN) -or ($excludeUsers -contains 'All')) {
        Write-Verbose "User Condition: User '$simUserUPN' is EXCLUDED by direct UPN or 'All'."
        return $false
    }
    if (($includeUsers -contains $simUserUPN) -or ($includeUsers -contains 'All')) {
        Write-Verbose "User Condition: User '$simUserUPN' is INCLUDED by direct UPN or 'All'."
        return $true
    }

    # If IncludeUsers is not 'All' and UPN is not directly in IncludeUsers, then it doesn't match based on users.
    # (Ignoring groups/roles for this simplified version)
    Write-Verbose "User Condition: User '$simUserUPN' not explicitly included and not 'All Users'. (Group/Role conditions not evaluated here)"
    return $false
}

function Test-ApplicationConditionMatch {
    param(
        [Parameter(Mandatory=$true)]
        [object]$appConditions, # Expects $PolicyToSimulate.Conditions.Applications object
        [Parameter(Mandatory=$true)]
        [string]$simApplicationId
    )

    if ($null -eq $appConditions) {
        Write-Verbose "Application condition in policy is null, considered a match for this aspect."
        return $true # No app condition specified means it applies to apps from this perspective
    }

    $includeApplications = @($appConditions.IncludeApplications)
    $excludeApplications = @($appConditions.ExcludeApplications)
    # UserActions are not evaluated in this simplified version

    if (($excludeApplications -contains $simApplicationId) -or ($excludeApplications -contains 'All')) {
        Write-Verbose "Application Condition: App '$simApplicationId' is EXCLUDED by ID or 'All'."
        return $false
    }
    if (($includeApplications -contains $simApplicationId) -or ($includeApplications -contains 'All')) {
        Write-Verbose "Application Condition: App '$simApplicationId' is INCLUDED by ID or 'All'."
        return $true
    }

    # If IncludeApplications is not 'All' and AppID is not directly in IncludeApplications.
    Write-Verbose "Application Condition: App '$simApplicationId' not explicitly included and not 'All Applications'."
    return $false
}


# --- SCRIPT MAIN LOGIC ---
Write-Host "Starting Policy Simulation for User: $SimUserPrincipalName, Application: $SimApplicationId" -ForegroundColor Cyan
Write-Warning "DISCLAIMER: This is a simplified local simulation, not a substitute for Azure AD 'What If'. It primarily checks User and Application conditions based on direct UPN/AppID matches and 'All' scopes. Group memberships, roles, device states, locations, and risk levels are NOT fully evaluated by this version unless explicitly added."

# --- 1. LOAD AND VALIDATE POLICY DEFINITION ---
Write-Host "`n--- Loading Policy Definition ---" -ForegroundColor Green
$PolicyToSimulate = $null
try {
    $PolicyToSimulate = Get-Content -Path $PolicyDefinitionPath -Raw | ConvertFrom-Json -ErrorAction Stop
    Write-Host "Successfully parsed policy definition file: $PolicyDefinitionPath"
}
catch {
    Write-Error "Failed to read or parse JSON from policy definition file: $PolicyDefinitionPath. Error: $($_.Exception.Message)"
    exit 1
}

if ($null -eq $PolicyToSimulate -or -not $PolicyToSimulate.PSObject.Properties['DisplayName'] -or `
    -not $PolicyToSimulate.PSObject.Properties['Conditions'] -or -not $PolicyToSimulate.PSObject.Properties['GrantControls']) {
    Write-Error "Policy definition from '$PolicyDefinitionPath' is invalid or missing essential top-level properties (DisplayName, Conditions, GrantControls)."
    exit 1
}
Write-Host "Policy to Simulate: '$($PolicyToSimulate.DisplayName)' (State: $($PolicyToSimulate.State))"


# --- 2. GATHER CONTEXTUAL DATA (Conceptual - requires actual implementation) ---
Write-Host "`n--- Contextual Data (Conceptual) ---" -ForegroundColor Green
Write-Host "[Conceptual] Fetching user groups, existing relevant policies for full 'What If' is not implemented in this version."
$existingApplicablePolicies = @()


# --- 3. EVALUATE THE POLICY-TO-SIMULATE AGAINST SIMULATED CONDITIONS ---
Write-Host "`n--- Policy Evaluation (Simulated) ---" -ForegroundColor Green
$userMatch = Test-UserConditionMatch -userConditions $PolicyToSimulate.Conditions.Users -simUserUPN $SimUserPrincipalName
$applicationMatch = Test-ApplicationConditionMatch -appConditions $PolicyToSimulate.Conditions.Applications -simApplicationId $SimApplicationId
# Add other condition checks here as implemented:
# $locationMatch = Test-LocationConditionMatch ...
# $deviceMatch = Test-DeviceConditionMatch ...
# $signInRiskMatch = Test-SignInRiskConditionMatch ...
# $userRiskMatch = Test-UserRiskConditionMatch ...

$allConditionsMet = $userMatch -and $applicationMatch # Currently only these two are checked

# --- 4. OUTPUT RESULT ---
Write-Host "`n--- Policy Evaluation Result ---" -ForegroundColor Cyan
Write-Host "Policy: '$($PolicyToSimulate.DisplayName)'"
Write-Host "Simulated User UPN: $SimUserPrincipalName"
Write-Host "Simulated Application ID: $SimApplicationId"
# (Add lines for other simulated conditions if they were used in checks)
Write-Host "User Condition Met: $userMatch"
Write-Host "Application Condition Met: $applicationMatch"

if ($allConditionsMet) {
    Write-Host "Outcome: Policy WOULD LIKELY APPLY based on simulated User and Application conditions." -ForegroundColor Green
    Write-Host "Grant Controls from this policy: $($PolicyToSimulate.GrantControls | ConvertTo-Json -Depth 3 -Compress)"
    if ($PolicyToSimulate.SessionControls) {
        Write-Host "Session Controls from this policy: $($PolicyToSimulate.SessionControls | ConvertTo-Json -Depth 3 -Compress)"
    }
} else {
    Write-Host "Outcome: Policy WOULD LIKELY NOT APPLY based on the evaluated User and Application conditions." -ForegroundColor Yellow
    Write-Host "Reason: UserMatch=$userMatch, ApplicationMatch=$applicationMatch. At least one primary condition was not met."
}

# --- 5. COMPARE WITH EXISTING APPLICABLE POLICIES (Conceptual) ---
Write-Host "`n--- Comparison with Existing Policies (Conceptual) ---" -ForegroundColor Green
Write-Host "[Conceptual] Analyzing interaction with other existing policies that might also apply is not implemented."
if ($existingApplicablePolicies.Count -gt 0) {
    foreach ($existingPolicy in $existingApplicablePolicies) {
        Write-Host "  - Considering existing policy '$($existingPolicy.displayName)'..."
    }
} else {
    Write-Host "  (Skipped - No other existing policies were loaded for comparison in this version)."
}

Write-Host "`nEnd of Policy Simulation." -ForegroundColor Cyan
