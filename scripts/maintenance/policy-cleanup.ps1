# policy-cleanup.ps1
# Automated cleanup of stale and redundant policies

param (
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    [int]$StaleThresholdDays = 90,
    [switch]$WhatIf
)

function Remove-StalePolicies {
    $staleDate = (Get-Date).AddDays(-$StaleThresholdDays)
    $policies = Get-MgIdentityConditionalAccessPolicy

    $stalePolicies = $policies | Where-Object {
        $_.ModifiedDateTime -lt $staleDate -and
        $_.State -eq "disabled"
    }

    foreach ($policy in $stalePolicies) {
        if ($WhatIf) {
            Write-Host "Would remove stale policy: $($policy.DisplayName)"
        }
        else {
            Remove-MgIdentityConditionalAccessPolicy -PolicyId $policy.Id
            Write-Host "Removed stale policy: $($policy.DisplayName)"
        }
    }
}

# Enhanced Find-RedundantPolicies function with simplified logic.
# This function identifies pairs of policies that are potentially redundant based on:
# - Identical GrantControls object.
# - Identical Users conditions (IncludeUsers and ExcludeUsers).
# - Identical Applications conditions (IncludeApplications and ExcludeApplications).
# - Both policies being in the same State (e.g., "enabled", "disabled").
# Note: True redundancy analysis is highly complex. This is a simplified approach.
function Find-RedundantPolicies([array]$policies) {
    $potentiallyRedundantSets = @()
    $checkedPolicyPairs = New-Object 'System.Collections.Generic.HashSet[string]'

    if ($policies.Count -lt 2) {
        Write-Verbose "Not enough policies to compare for redundancy."
        return $potentiallyRedundantSets
    }

    for ($i = 0; $i -lt $policies.Count; $i++) {
        for ($j = $i + 1; $j -lt $policies.Count; $j++) {
            $policyA = $policies[$i]
            $policyB = $policies[$j]

            # Create a unique key for the pair to avoid re-checking or duplicate pairs in different orders
            $pairKey = ($policyA.Id, $policyB.Id | Sort-Object) -join '|'
            if ($checkedPolicyPairs.Contains($pairKey)) {
                continue
            }

            # Criteria 1: Same State
            if ($policyA.State -ne $policyB.State) {
                continue
            }

            # Criteria 2: Identical Grant Controls (simplistic: compare string representation)
            # A more robust check would compare each property of GrantControls.
            $grantControlsA = $policyA.GrantControls | ConvertTo-Json -Depth 5 -Compress
            $grantControlsB = $policyB.GrantControls | ConvertTo-Json -Depth 5 -Compress
            if ($grantControlsA -ne $grantControlsB) {
                continue
            }

            # Criteria 3: Identical User Conditions
            # Comparing arrays requires converting them to a comparable string or element-wise comparison.
            $usersA_Include = ($policyA.Conditions.Users.IncludeUsers | Sort-Object) -join ','
            $usersB_Include = ($policyB.Conditions.Users.IncludeUsers | Sort-Object) -join ','
            $usersA_Exclude = ($policyA.Conditions.Users.ExcludeUsers | Sort-Object) -join ','
            $usersB_Exclude = ($policyB.Conditions.Users.ExcludeUsers | Sort-Object) -join ','

            if (($usersA_Include -ne $usersB_Include) -or ($usersA_Exclude -ne $usersB_Exclude)) {
                continue
            }

            # Criteria 4: Identical Application Conditions
            $appsA_Include = ($policyA.Conditions.Applications.IncludeApplications | Sort-Object) -join ','
            $appsB_Include = ($policyB.Conditions.Applications.IncludeApplications | Sort-Object) -join ','
            $appsA_Exclude = ($policyA.Conditions.Applications.ExcludeApplications | Sort-Object) -join ','
            $appsB_Exclude = ($policyB.Conditions.Applications.ExcludeApplications | Sort-Object) -join ','

            if (($appsA_Include -ne $appsB_Include) -or ($appsA_Exclude -ne $appsB_Exclude)) {
                continue
            }

            # If all checks pass, consider them a potentially redundant pair
            $reason = "Identical grant controls, user conditions, application conditions, and state."
            $potentiallyRedundantSets += @{
                Policies = @($policyA, $policyB)
                Reason   = $reason
            }
            $checkedPolicyPairs.Add($pairKey) | Out-Null
        }
    }

    if ($potentiallyRedundantSets.Count -gt 0) {
        Write-Host "Found $($potentiallyRedundantSets.Count) potentially redundant policy pair(s) based on simplified checks."
    } else {
        Write-Host "No potentially redundant policy pairs found based on simplified checks."
    }
    return $potentiallyRedundantSets
}

# Updated Merge-Policies function (still a placeholder for actual merging).
# Merging policies is a high-risk operation and should be done with extreme caution,
# typically after manual review and with a clear understanding of the combined impact.
function Merge-Policies([array]$policiesToMerge) {
    Write-Warning "Merge-Policies is a high-risk operation and NOT fully implemented. It currently performs NO merge actions."
    Write-Warning "Manual review of the following policies is required to determine appropriate merge strategy:"
    foreach ($policy in $policiesToMerge) {
        Write-Warning "  - Name: '$($policy.DisplayName)', ID: '$($policy.Id)'"
    }
    # In a real implementation, this function would:
    # 1. Define a strategy for combining conditions (e.g., union of users, apps).
    # 2. Define how to handle grant controls (usually they are identical if found by Find-RedundantPolicies).
    # 3. Create a new policy with the combined definition.
    # 4. Potentially disable or delete the old policies after successful creation and testing of the new one.
    # This process requires careful planning and testing.
}

# Updated Merge-RedundantPolicies (calling function)
function Merge-RedundantPolicies {
    param(
        [array]$AllPolicies, # Pass all policies to avoid repeated Get-MgIdentityConditionalAccessPolicy calls
        [switch]$WhatIfMode
    )

    Write-Host "Attempting to find redundant policies..."
    $redundantSets = Find-RedundantPolicies -policies $AllPolicies

    if ($redundantSets.Count -eq 0) {
        # Message now comes from Find-RedundantPolicies
        return
    }

    Write-Host "Processing potentially redundant policy sets..."
    foreach ($set in $redundantSets) {
        $policyNames = $set.Policies | ForEach-Object { $_.DisplayName }
        Write-Host ("-" * 40)
        Write-Host "Found potentially redundant set: $($policyNames -join ', ')"
        Write-Host "Reason: $($set.Reason)"

        if ($WhatIfMode) {
            Write-Host "[WhatIf] Would suggest manual review for merging policies: $($policyNames -join ', ')"
        }
        else {
            # Call Merge-Policies, which currently only issues warnings and performs no action.
            Write-Host "Calling Merge-Policies (currently a non-acting placeholder) for the set above."
            Merge-Policies $set.Policies
            Write-Host "Merge-Policies call completed. Manual review and action are required."
        }
    }
}

# Execute cleanup
Write-Host "Connecting to Microsoft Graph..."
# Add error handling for connection
try {
    Connect-MgGraph -TenantId $TenantId -ErrorAction Stop
    Write-Host "Successfully connected to Microsoft Graph."
}
catch {
    Write-Error "Failed to connect to Microsoft Graph. $($_.Exception.Message)"
    # Optionally exit the script if connection fails
    # exit 1
    # For cleanup, we might want to proceed if possible, or ensure this is handled.
    # For now, functions that use Get-Mg will fail if not connected.
}

Write-Host "Starting policy cleanup process..."

# Stale policy removal
Write-Host ("="*50)
Write-Host "Step 1: Removing Stale Policies..."
Remove-StalePolicies -WhatIf:$WhatIf # Pass WhatIf switch

# Redundant policy identification and (manual) merge suggestion
Write-Host ("="*50)
Write-Host "Step 2: Identifying Potentially Redundant Policies..."
# Fetch all policies once for efficiency
$allCaPolicies = Get-MgIdentityConditionalAccessPolicy
if ($null -eq $allCaPolicies) {
    Write-Warning "Could not retrieve Conditional Access policies. Skipping redundancy check."
} else {
    Merge-RedundantPolicies -AllPolicies $allCaPolicies -WhatIfMode:$WhatIf # Pass WhatIf switch
}

Write-Host ("="*50)
Write-Host "Policy cleanup process finished."