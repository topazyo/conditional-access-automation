# scripts/tools/invoke_policy_simulation.ps1
# Script to perform a simplified, local "What If" simulation for a CA policy definition.
# DISCLAIMER: This is a conceptual tool and NOT a replacement for Azure AD's "What If" functionality.
# It provides a local evaluation based on provided inputs and existing policy comparison.

param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Leaf -ErrorAction Stop})]
    [string]$PolicyDefinitionPath,

    [Parameter(Mandatory=$true)]
    [string]$SimUserPrincipalName,

    [Parameter(Mandatory=$false)]
    [string]$SimUserLocationId,

    [Parameter(Mandatory=$false)]
    [ValidateSet('android', 'iOS', 'windows', 'macOS', 'linux', 'all', IgnoreCase = $true)]
    [string]$SimUserDevicePlatform,

    [Parameter(Mandatory=$false)]
    [string]$SimUserDeviceState, # Not evaluated in this version

    [Parameter(Mandatory=$true)]
    [string]$SimApplicationId,

    [Parameter(Mandatory=$false)]
    [ValidateSet('low', 'medium', 'high', 'noRisk', IgnoreCase = $true)] # Added noRisk as it's a valid CA value
    [string]$SimSignInRiskLevel,

    [Parameter(Mandatory=$false)]
    [ValidateSet('low', 'medium', 'high', 'noRisk', 'none', IgnoreCase = $true)] # Added noRisk, none as valid CA values
    [string]$SimUserRiskLevel
)

# --- HELPER FUNCTIONS ---
function Test-UserConditionMatch {
    param(
        [Parameter(Mandatory=$true)]
        [object]$userConditions,
        [Parameter(Mandatory=$true)]
        [string]$simUserUPN
    )
    if ($null -eq $userConditions) { Write-Verbose "User condition: Policy defines no user conditions (applies to all users from this aspect)."; return $true }
    $includeUsers = @($userConditions.IncludeUsers)
    $excludeUsers = @($userConditions.ExcludeUsers)
    if (($excludeUsers -contains $simUserUPN) -or ($excludeUsers -contains 'All')) { Write-Verbose "User Condition: User '$simUserUPN' EXCLUDED."; return $false }
    if (($includeUsers -contains $simUserUPN) -or ($includeUsers -contains 'All')) { Write-Verbose "User Condition: User '$simUserUPN' INCLUDED."; return $true }
    Write-Verbose "User Condition: User '$simUserUPN' not explicitly included/excluded by UPN (group/role conditions not evaluated here)."
    return $false # Default if not explicitly included by UPN or 'All' (and not excluded)
}

function Test-ApplicationConditionMatch {
    param(
        [Parameter(Mandatory=$true)]
        [object]$appConditions,
        [Parameter(Mandatory=$true)]
        [string]$simApplicationId
    )
    if ($null -eq $appConditions) { Write-Verbose "Application condition: Policy defines no app conditions (applies to all apps from this aspect)."; return $true }
    $includeApplications = @($appConditions.IncludeApplications)
    $excludeApplications = @($appConditions.ExcludeApplications)
    if (($excludeApplications -contains $simApplicationId) -or ($excludeApplications -contains 'All')) { Write-Verbose "Application Condition: App '$simApplicationId' EXCLUDED."; return $false }
    if (($includeApplications -contains $simApplicationId) -or ($includeApplications -contains 'All')) { Write-Verbose "Application Condition: App '$simApplicationId' INCLUDED."; return $true }
    Write-Verbose "Application Condition: App '$simApplicationId' not explicitly included/excluded."
    return $false # Default if not explicitly included by AppID or 'All' (and not excluded)
}

function Test-LocationConditionMatch {
    param(
        [Parameter(Mandatory=$true)]
        [object]$locationConditions,
        [Parameter(Mandatory=$false)]
        [string]$simUserLocationId
    )
    if ($null -eq $locationConditions -or ($null -eq $locationConditions.IncludeLocations -and $null -eq $locationConditions.ExcludeLocations)) { Write-Verbose "Location condition: Policy defines no location conditions."; return $true }
    if ([string]::IsNullOrEmpty($simUserLocationId)) { Write-Verbose "Location condition: Simulated user location not provided; cannot match specific location conditions."; return $true } # Or false if policy requires specific location? For now, true.

    $includeLocations = @($locationConditions.IncludeLocations)
    $excludeLocations = @($locationConditions.ExcludeLocations)

    if (($excludeLocations -contains $simUserLocationId) -or ($excludeLocations -contains 'All')) { Write-Verbose "Location Condition: Location '$simUserLocationId' EXCLUDED."; return $false }

    # If 'AllTrusted' is included and user provides a location, we cannot verify its trusted status here.
    # For this simulation, if policy includes 'AllTrusted', we assume any provided user location could be one of them.
    # This is a known limitation of local simulation.
    if ($includeLocations -contains 'AllTrusted') { Write-Verbose "Location Condition: Policy includes 'AllTrusted'. Assuming simulated location '$simUserLocationId' COULD BE trusted (local sim limitation)."; return $true }

    if (($includeLocations -contains $simUserLocationId) -or ($includeLocations -contains 'All')) { Write-Verbose "Location Condition: Location '$simUserLocationId' INCLUDED."; return $true }

    if ($includeLocations.Count -gt 0 -and -not ($includeLocations -contains 'All') -and -not ($includeLocations -contains 'AllTrusted')) {
        Write-Verbose "Location Condition: Location '$simUserLocationId' not in policy's included locations: $($includeLocations -join ', ')."
        return $false # Policy requires specific locations, and sim location doesn't match
    }
    return $true # Default if no specific include implies match, or if only exclusions were specified and sim location wasn't excluded.
}

function Test-PlatformConditionMatch {
    param(
        [Parameter(Mandatory=$true)]
        [object]$platformConditions,
        [Parameter(Mandatory=$false)]
        [string]$simUserDevicePlatform
    )
    if ($null -eq $platformConditions -or ($null -eq $platformConditions.IncludePlatforms -and $null -eq $platformConditions.ExcludePlatforms)) { Write-Verbose "Platform condition: Policy defines no platform conditions."; return $true }
    if ([string]::IsNullOrEmpty($simUserDevicePlatform)) { Write-Verbose "Platform condition: Simulated device platform not provided; cannot match specific platform conditions."; return $true } # Or false? For now, true.

    $includePlatforms = @($platformConditions.IncludePlatforms)
    $excludePlatforms = @($platformConditions.ExcludePlatforms)

    if (($excludePlatforms -contains $simUserDevicePlatform) -or ($excludePlatforms -contains 'all')) { Write-Verbose "Platform Condition: Platform '$simUserDevicePlatform' EXCLUDED."; return $false } # 'all' is a keyword for platforms too
    if (($includePlatforms -contains $simUserDevicePlatform) -or ($includePlatforms -contains 'all')) { Write-Verbose "Platform Condition: Platform '$simUserDevicePlatform' INCLUDED."; return $true }

    if ($includePlatforms.Count -gt 0 -and -not ($includePlatforms -contains 'all')) {
         Write-Verbose "Platform Condition: Platform '$simUserDevicePlatform' not in policy's included platforms: $($includePlatforms -join ', ')."
        return $false # Policy requires specific platforms, and sim platform doesn't match
    }
    return $true # Default if no specific include implies match, or only exclusions specified.
}

function Test-RiskLevelConditionMatch {
    param(
        [Parameter(Mandatory=$true)]
        [array]$policyRiskLevels, # e.g., $PolicyToSimulate.Conditions.SignInRiskLevels
        [Parameter(Mandatory=$false)]
        [string]$simRiskLevel,
        [Parameter(Mandatory=$true)]
        [string]$riskTypeForLogging # e.g., "Sign-in" or "User"
    )
    $policyRiskLevelsNormalized = @($policyRiskLevels) # Ensure array even if single or null

    if ($policyRiskLevelsNormalized.Count -eq 0) { Write-Verbose "$riskTypeForLogging Risk condition: Policy defines no $riskTypeForLogging risk conditions."; return $true } # Policy doesn't care

    # If policy specifies risk, simulation must provide a risk level for evaluation
    if ([string]::IsNullOrEmpty($simRiskLevel)) {
        Write-Verbose "$riskTypeForLogging Risk condition: Policy requires $riskTypeForLogging risk, but no simulated $riskTypeForLogging risk level provided. Condition evaluated as NOT met."
        return $false
    }

    if ($policyRiskLevelsNormalized -contains $simRiskLevel) { # Comparison is case-insensitive by default for -contains with strings
        Write-Verbose "$riskTypeForLogging Risk condition: Simulated risk '$simRiskLevel' MATCHES policy levels ($($policyRiskLevelsNormalized -join ', '))."
        return $true
    }

    Write-Verbose "$riskTypeForLogging Risk condition: Simulated risk '$simRiskLevel' does NOT MATCH policy levels ($($policyRiskLevelsNormalized -join ', '))."
    return $false
}


# --- SCRIPT MAIN LOGIC ---
Write-Host "Starting Policy Simulation for User: $SimUserPrincipalName, Application: $SimApplicationId" -ForegroundColor Cyan
Write-Warning "DISCLAIMER: This is a simplified local simulation, not a substitute for Azure AD 'What If'. It primarily checks User, Application, Location, Platform, and Risk Level conditions based on direct matches and 'All' scopes. Group memberships, roles, and detailed device states are NOT fully evaluated by this version unless explicitly added."

# --- 1. LOAD AND VALIDATE POLICY DEFINITION ---
Write-Host "`n--- Loading Policy Definition ---" -ForegroundColor Green
$policyToSimulate = $null # Renamed from $PolicyToSimulate
try {
    $policyToSimulate = Get-Content -Path $PolicyDefinitionPath -Raw | ConvertFrom-Json -ErrorAction Stop # Renamed
    Write-Host "Successfully parsed policy definition file: $PolicyDefinitionPath"
}
catch {
    Write-Error "Failed to read or parse JSON from policy definition file: $PolicyDefinitionPath. Error: $($_.Exception.Message)"
    exit 1
}

if ($null -eq $policyToSimulate -or -not $policyToSimulate.PSObject.Properties['DisplayName'] -or ` # Renamed
    -not $policyToSimulate.PSObject.Properties['Conditions'] -or -not $policyToSimulate.PSObject.Properties['GrantControls']) { # Renamed
    Write-Error "Policy definition from '$PolicyDefinitionPath' is invalid or missing essential top-level properties (DisplayName, Conditions, GrantControls)."
    exit 1
}
Write-Host "Policy to Simulate: '$($policyToSimulate.DisplayName)' (State: $($policyToSimulate.State))" # Renamed


# --- 2. GATHER CONTEXTUAL DATA (Conceptual) ---
Write-Host "`n--- Contextual Data (Conceptual) ---" -ForegroundColor Green
Write-Host "[Conceptual] Fetching user groups, existing relevant policies for full 'What If' is not implemented in this version."
$existingApplicablePolicies = @()


# --- 3. EVALUATE THE POLICY-TO-SIMULATE AGAINST SIMULATED CONDITIONS ---
Write-Host "`n--- Policy Evaluation (Simulated) ---" -ForegroundColor Green
$userMatch = Test-UserConditionMatch -userConditions $policyToSimulate.Conditions.Users -simUserUPN $SimUserPrincipalName # Renamed
$applicationMatch = Test-ApplicationConditionMatch -appConditions $policyToSimulate.Conditions.Applications -simApplicationId $SimApplicationId # Renamed
$locationMatch = Test-LocationConditionMatch -locationConditions $policyToSimulate.Conditions.Locations -simUserLocationId $SimUserLocationId # Renamed
$platformMatch = Test-PlatformConditionMatch -platformConditions $policyToSimulate.Conditions.Platforms -simUserDevicePlatform $SimUserDevicePlatform # Renamed
$signInRiskMatch = Test-RiskLevelConditionMatch -policyRiskLevels $policyToSimulate.Conditions.SignInRiskLevels -simRiskLevel $SimSignInRiskLevel -riskTypeForLogging "Sign-in" # Renamed
$userRiskMatch = Test-RiskLevelConditionMatch -policyRiskLevels $policyToSimulate.Conditions.UserRiskLevels -simRiskLevel $SimUserRiskLevel -riskTypeForLogging "User" # Renamed

Write-Host "Device Filter/State Condition: Not evaluated by this script version." # Placeholder for $SimUserDeviceState

$allConditionsMet = $userMatch -and $applicationMatch -and $locationMatch -and $platformMatch -and $signInRiskMatch -and $userRiskMatch

# --- 4. OUTPUT RESULT ---
Write-Host "`n--- Policy Evaluation Result ---" -ForegroundColor Cyan
Write-Host "Policy: '$($policyToSimulate.DisplayName)'" # Renamed
Write-Host "Simulated User UPN: $SimUserPrincipalName"
Write-Host "Simulated Application ID: $SimApplicationId"
Write-Host "Simulated Location ID: $(if ($SimUserLocationId) {$SimUserLocationId} else {'Not Provided'})"
Write-Host "Simulated Device Platform: $(if ($SimUserDevicePlatform) {$SimUserDevicePlatform} else {'Not Provided'})"
Write-Host "Simulated Sign-in Risk: $(if ($SimSignInRiskLevel) {$SimSignInRiskLevel} else {'Not Provided'})"
Write-Host "Simulated User Risk: $(if ($SimUserRiskLevel) {$SimUserRiskLevel} else {'Not Provided'})"
Write-Host "---"
Write-Host "User Condition Met: $userMatch"
Write-Host "Application Condition Met: $applicationMatch"
Write-Host "Location Condition Met: $locationMatch"
Write-Host "Platform Condition Met: $platformMatch"
Write-Host "Sign-in Risk Condition Met: $signInRiskMatch"
Write-Host "User Risk Condition Met: $userRiskMatch"


if ($allConditionsMet) {
    Write-Host "Outcome: Policy WOULD LIKELY APPLY based on simulated User, Application, Location, Platform, Sign-in Risk, and User Risk conditions." -ForegroundColor Green
    Write-Host "Grant Controls from this policy: $($policyToSimulate.GrantControls | ConvertTo-Json -Depth 3 -Compress)" # Renamed
    if ($policyToSimulate.SessionControls) { # Renamed
        Write-Host "Session Controls from this policy: $($policyToSimulate.SessionControls | ConvertTo-Json -Depth 3 -Compress)" # Renamed
    }
} else {
    Write-Host "Outcome: Policy WOULD LIKELY NOT APPLY based on the evaluated conditions." -ForegroundColor Yellow
    Write-Host "Reason: UserMatch=$userMatch, AppMatch=$applicationMatch, LocationMatch=$locationMatch, PlatformMatch=$platformMatch, SignInRiskMatch=$signInRiskMatch, UserRiskMatch=$userRiskMatch. At least one condition was not met or not satisfied by simulation parameters."
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
