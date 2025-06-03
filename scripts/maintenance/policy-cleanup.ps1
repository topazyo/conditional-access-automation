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

# Placeholder function to find redundant policies.
# In a real implementation, this would involve complex logic to compare policies
# based on their conditions (users, applications, locations, etc.) and grant controls.
function Find-RedundantPolicies([array]$policies) {
    Write-Warning "Find-RedundantPolicies is not fully implemented and will return an empty list."
    # Example of what it might return if it found redundant sets:
    # return @(
    #     @{ Policies = @($policy1, $policy2); MergedPolicySuggestion = @{ DisplayName = "Merged Policy 1-2"} }
    # )
    return @()
}

# Placeholder function to merge policies.
# In a real implementation, this would involve creating a new policy that combines
# the conditions and controls of the input policies, then potentially disabling or
# deleting the original policies.
function Merge-Policies([array]$policiesToMerge) {
    Write-Warning "Merge-Policies is not fully implemented. No policies will be merged."
    # Example logic:
    # $newPolicyDefinition = # ... logic to combine policies ...
    # New-MgIdentityConditionalAccessPolicy -BodyParameter $newPolicyDefinition
    # foreach ($oldPolicy in $policiesToMerge) { Remove-MgIdentityConditionalAccessPolicy -PolicyId $oldPolicy.Id }
}

function Merge-RedundantPolicies {
    $policies = Get-MgIdentityConditionalAccessPolicy
    $redundantSets = Find-RedundantPolicies $policies

    if ($redundantSets.Count -eq 0) {
        Write-Host "No redundant policy sets found to merge by the current basic implementation."
        return
    }

    foreach ($set in $redundantSets) {
        if ($WhatIf) {
            # Assuming $set.Policies is an array of policy objects with a DisplayName property
            $policyNames = $set.Policies | ForEach-Object {$_.DisplayName}
            Write-Host "Would attempt to merge redundant policies: $($policyNames -join ', ')"
        }
        else {
            # This part would change based on how Merge-Policies is implemented
            # For now, it just calls the placeholder which does nothing.
            Merge-Policies $set.Policies
            # If Merge-Policies actually created a new policy and returned it:
            # Write-Host "Merged redundant policies into: $($mergedPolicy.DisplayName)"
            # For now, since it's a placeholder:
            Write-Host "Merge-Policies was called for policies (placeholder action): $($set.Policies.DisplayName -join ', ')"
        }
    }
}

# Execute cleanup
# Ensure connection is established before calling functions that might use Get-Mg commands implicitly or explicitly
# Assuming Connect-MgGraph is appropriately handled, e.g., checking for existing connection or specific scopes.
# For safety, it's often better to pass the connection or ensure it's available.
Write-Host "Connecting to Microsoft Graph..."
Connect-MgGraph -TenantId $TenantId # Consider error handling or checking connection status

Write-Host "Starting policy cleanup process..."
Remove-StalePolicies
Merge-RedundantPolicies

Write-Host "Policy cleanup process finished."