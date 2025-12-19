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

function Merge-RedundantPolicies {
    $policies = Get-MgIdentityConditionalAccessPolicy
    $redundantSets = Find-RedundantPolicies $policies

    foreach ($set in $redundantSets) {
        if ($WhatIf) {
            Write-Host "Would merge redundant policies: $($set.Policies.DisplayName -join ', ')"
        }
        else {
            Merge-Policies $set.Policies
            Write-Host "Merged redundant policies into: $($set.MergedPolicy.DisplayName)"
        }
    }
}

# Execute cleanup
Connect-MgGraph -TenantId $TenantId
Remove-StalePolicies
Merge-RedundantPolicies