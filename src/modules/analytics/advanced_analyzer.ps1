# src/modules/analytics/advanced_analyzer.ps1
# Module for Advanced Conditional Access Policy Analytics

class AdvancedPolicyAnalyzer {
    # Hidden properties for potential data sources or configurations
    hidden [array]$AllPolicies
    hidden [array]$SignInLogs
    hidden [array]$AuditLogs

    AdvancedPolicyAnalyzer([array]$policies, [array]$signInLogs, [array]$auditLogs) {
        if ($null -eq $policies -or $policies.Count -eq 0) {
            Write-Warning "AdvancedPolicyAnalyzer initialized with no policies. Most analytics functions will not yield results."
        } elseif ($null -eq $policies[0].PSObject.Properties['Id'] -or $null -eq $policies[0].PSObject.Properties['DisplayName']) {
            Write-Warning "AdvancedPolicyAnalyzer initialized with an array that does not appear to contain valid policy objects (missing Id or DisplayName). Analytics may fail."
        }
        $this.AllPolicies = @($policies) # Ensure it's an array
        $this.SignInLogs = $signInLogs
        $this.AuditLogs = $auditLogs
        Write-Verbose "AdvancedPolicyAnalyzer initialized with $($this.AllPolicies.Count) policies."
    }

    [hashtable]GeneratePolicyOverlapReport() {
        Write-Verbose "Generating policy overlap report..."
        $overlapSets = [System.Collections.Generic.List[hashtable]]::new()
        $checkedPairs = [System.Collections.Generic.HashSet[string]]::new()

        if ($this.AllPolicies.Count -lt 2) {
            Write-Host "Less than two policies provided; no overlap analysis possible."
            return @{ OverlapSets = @() }
        }

        for ($i = 0; $i -lt $this.AllPolicies.Count; $i++) {
            for ($j = $i + 1; $j -lt $this.AllPolicies.Count; $j++) {
                $policyA = $this.AllPolicies[$i]
                $policyB = $this.AllPolicies[$j]

                $pairKey = ($policyA.Id, $policyB.Id | Sort-Object) -join '|'
                if ($checkedPairs.Contains($pairKey)) {
                    continue
                }
                $checkedPairs.Add($pairKey) | Out-Null

                if ($policyA.State -notin @('enabled', 'enabledForReportingButNotEnforced') -or
                    $policyB.State -notin @('enabled', 'enabledForReportingButNotEnforced')) {
                    Write-Verbose "Skipping pair $($policyA.DisplayName) & $($policyB.DisplayName) as one or both are not enabled."
                    continue
                }

                Write-Verbose "Comparing policy '$($policyA.DisplayName)' with '$($policyB.DisplayName)'"
                $userOverlap = $this.CompareUserConditionOverlap($policyA.Conditions.Users, $policyB.Conditions.Users)
                $appOverlap = $this.CompareApplicationConditionOverlap($policyA.Conditions.Applications, $policyB.Conditions.Applications)

                if ($userOverlap.OverlapType -ne 'None' -and $appOverlap.OverlapType -ne 'None') {
                    $overlappingConditions = @{
                        Users = $userOverlap.Description
                        Applications = $appOverlap.Description
                    }
                    $combinedGrantControlsSummary = $this.SummarizeCombinedGrantControls($policyA.GrantControls, $policyB.GrantControls)

                    $notes = "Policies '$($policyA.DisplayName)' and '$($policyB.DisplayName)' show overlap in user and application scope. "
                    $notes += "Review their grant controls and conditions to ensure intended cumulative effect."
                    if ($userOverlap.OverlapType -eq 'Full' -and $appOverlap.OverlapType -eq 'Full') {
                        $notes += " Conditions appear to be identical for users and applications."
                    }

                    $overlapSets.Add(@{
                        Policies = @("$($policyA.DisplayName) (Id: $($policyA.Id))", "$($policyB.DisplayName) (Id: $($policyB.Id))")
                        OverlappingConditions = $overlappingConditions
                        CombinedGrantControls = $combinedGrantControlsSummary
                        UserOverlapType = $userOverlap.OverlapType
                        AppOverlapType = $appOverlap.OverlapType
                        Notes = $notes
                    })
                }
            }
        }
        Write-Verbose "Policy overlap report generation complete. Found $($overlapSets.Count) overlapping sets."
        return @{ OverlapSets = $overlapSets.ToArray() }
    }

    hidden [hashtable]CompareUserConditionOverlap([object]$usersA, [object]$usersB) {
        if ($null -eq $usersA -or $null -eq $usersB) { return @{ OverlapType = 'Unknown'; Description = "One or both user conditions are null." } }

        $normA = @{
            IncludeUsers = @($usersA.IncludeUsers)
            ExcludeUsers = @($usersA.ExcludeUsers)
            IncludeGroups = @($usersA.IncludeGroups)
            ExcludeGroups = @($usersA.ExcludeGroups)
            IncludeGuests = @($usersA.IncludeGuestsOrExternalUsers)
        }
        $normB = @{
            IncludeUsers = @($usersB.IncludeUsers)
            ExcludeUsers = @($usersB.ExcludeUsers)
            IncludeGroups = @($usersB.IncludeGroups)
            ExcludeGroups = @($usersB.ExcludeGroups)
            IncludeGuests = @($usersB.IncludeGuestsOrExternalUsers)
        }

        $isAAllUsers = $normA.IncludeUsers -contains 'All' -or $normA.IncludeGuests -contains 'all'
        $isBAllUsers = $normB.IncludeUsers -contains 'All' -or $normB.IncludeGuests -contains 'all'

        if ($isAAllUsers -and $isBAllUsers) {
            return @{ OverlapType = 'Full'; Description = "Both policies target 'All Users' (or all guests)." }
        }
        if ($isAAllUsers) {
            if (($normB.IncludeUsers.Count + $normB.IncludeGroups.Count + $normB.IncludeGuests.Count) > 0) {
                 return @{ OverlapType = 'Subset'; Description = "Policy A targets 'All Users', potentially containing users from Policy B's specific scope ($($normB.IncludeUsers -join ', '), Groups: $($normB.IncludeGroups -join ', '), Guests: $($normB.IncludeGuests -join ', '))." }
            }
        }
        if ($isBAllUsers) {
            if (($normA.IncludeUsers.Count + $normA.IncludeGroups.Count + $normA.IncludeGuests.Count) > 0) {
                return @{ OverlapType = 'Subset'; Description = "Policy B targets 'All Users', potentially containing users from Policy A's specific scope ($($normA.IncludeUsers -join ', '), Groups: $($normA.IncludeGroups -join ', '), Guests: $($normA.IncludeGuests -join ', '))." }
            }
        }

        $intersectingUsers = Compare-Object $normA.IncludeUsers $normB.IncludeUsers -IncludeEqual -ExcludeDifferent -PassThru
        $intersectingGroups = Compare-Object $normA.IncludeGroups $normB.IncludeGroups -IncludeEqual -ExcludeDifferent -PassThru
        $intersectingGuests = Compare-Object $normA.IncludeGuests $normB.IncludeGuests -IncludeEqual -ExcludeDifferent -PassThru

        if ($intersectingUsers.Count -gt 0 -or $intersectingGroups.Count -gt 0 -or $intersectingGuests.Count -gt 0) {
            $details = "Partial overlap on Users: $(@($intersectingUsers) -join ', '), Groups: $(@($intersectingGroups) -join ', '), Guests: $(@($intersectingGuests) -join ', ')"
            return @{ OverlapType = 'Partial'; Description = $details }
        }

        return @{ OverlapType = 'None'; Description = "No direct overlap found in included users, groups, or guest types based on simplified check." }
    }

    hidden [hashtable]CompareApplicationConditionOverlap([object]$appsA, [object]$appsB) {
        if ($null -eq $appsA -or $null -eq $appsB) { return @{ OverlapType = 'Unknown'; Description = "One or both application conditions are null." } }

        $normA = @{
            IncludeApplications = @($appsA.IncludeApplications)
            ExcludeApplications = @($appsA.ExcludeApplications)
            IncludeUserActions = @($appsA.IncludeUserActions)
        }
        $normB = @{
            IncludeApplications = @($appsB.IncludeApplications)
            ExcludeApplications = @($appsB.ExcludeApplications)
            IncludeUserActions = @($appsB.IncludeUserActions)
        }

        $isAAllApps = $normA.IncludeApplications -contains 'All'
        $isBAllApps = $normB.IncludeApplications -contains 'All'

        if ($isAAllApps -and $isBAllApps) {
            return @{ OverlapType = 'Full'; Description = "Both policies target 'All Applications'." }
        }
        if ($isAAllApps) {
            if ($normB.IncludeApplications.Count > 0 -and $normB.IncludeApplications[0] -ne 'None') {
                return @{ OverlapType = 'Subset'; Description = "Policy A targets 'All Applications', potentially covering applications from Policy B's specific scope ($($normB.IncludeApplications -join ', '))." }
            }
        }
        if ($isBAllApps) {
             if ($normA.IncludeApplications.Count > 0 -and $normA.IncludeApplications[0] -ne 'None') {
                return @{ OverlapType = 'Subset'; Description = "Policy B targets 'All Applications', potentially covering applications from Policy A's specific scope ($($normA.IncludeApplications -join ', '))." }
            }
        }

        $intersectingApps = Compare-Object $normA.IncludeApplications $normB.IncludeApplications -IncludeEqual -ExcludeDifferent -PassThru

        if ($intersectingApps.Count -gt 0) {
            $actionsNote = ""
            if (($normA.IncludeUserActions.Count + $normB.IncludeUserActions.Count) > 0) {
                if (($normA.IncludeUserActions -join ';') -ne ($normB.IncludeUserActions -join ';')) {
                    $actionsNote = " User actions differ (A: $($normA.IncludeUserActions -join ', '), B: $($normB.IncludeUserActions -join ', '))."
                } else {
                    $actionsNote = " User actions are similar/identical."
                }
            }
            return @{ OverlapType = 'Partial'; Description = "Partial overlap on Applications: $(@($intersectingApps) -join ', ').$actionsNote" }
        }

        if ($normA.IncludeApplications.Count -eq 0 -and $normA.IncludeUserActions.Count -gt 0 -and `
            $normB.IncludeApplications.Count -eq 0 -and $normB.IncludeUserActions.Count -gt 0) {
            $intersectingActions = Compare-Object $normA.IncludeUserActions $normB.IncludeUserActions -IncludeEqual -ExcludeDifferent -PassThru
            if ($intersectingActions.Count -gt 0) {
                 return @{ OverlapType = 'Partial'; Description = "Partial overlap on UserActions only: $(@($intersectingActions) -join ', ')." }
            }
        }

        return @{ OverlapType = 'None'; Description = "No direct overlap found in included applications or user actions based on simplified check." }
    }

    hidden [string]SummarizeCombinedGrantControls([object]$grantsA, [object]$grantsB) {
        $summaryA = "Policy A: "
        if ($null -ne $grantsA) {
            $summaryA += "Operator '$($grantsA.Operator)', Controls '$(@($grantsA.BuiltInControls) -join ', ')'"
            if ($null -ne $grantsA.CustomAuthenticationFactors) { $summaryA += ", CustomAuthFactors present."}
        } else {
            $summaryA += "No grant controls (e.g. Block access, or implicit Allow if conditions met but no controls specified)."
        }

        $summaryB = "Policy B: "
        if ($null -ne $grantsB) {
            $summaryB += "Operator '$($grantsB.Operator)', Controls '$(@($grantsB.BuiltInControls) -join ', ')'"
             if ($null -ne $grantsB.CustomAuthenticationFactors) { $summaryB += ", CustomAuthFactors present."}
        } else {
            $summaryB += "No grant controls (e.g. Block access, or implicit Allow if conditions met but no controls specified)."
        }

        return "$summaryA; $summaryB. Effective controls depend on how conditions of both policies evaluate for a given sign-in and the 'most restrictive' principle for combined grant controls."
    }

    hidden [bool]DoesPolicyApplyToUser([object]$policy, [string]$userUPN) {
        Write-Warning "User group membership check is not performed in this simplified version of DoesPolicyApplyToUser. Coverage analysis might be incomplete for group-assigned policies."
        if ($null -eq $policy -or $null -eq $policy.Conditions -or $null -eq $policy.Conditions.Users) { return $false }

        $usersCondition = $policy.Conditions.Users
        $includeUsers = @($usersCondition.IncludeUsers)
        $excludeUsers = @($usersCondition.ExcludeUsers)

        if (($excludeUsers -contains $userUPN) -or ($excludeUsers -contains 'All')) {
            return $false
        }
        if (($includeUsers -contains $userUPN) -or ($includeUsers -contains 'All')) {
            return $true
        }
        return $false
    }

    hidden [bool]DoesPolicyApplyToApplication([object]$policy, [string]$appIdentifier) {
        if ($null -eq $policy -or $null -eq $policy.Conditions -or $null -eq $policy.Conditions.Applications) { return $false }

        $appsCondition = $policy.Conditions.Applications
        $includeApps = @($appsCondition.IncludeApplications)
        $excludeApps = @($appsCondition.ExcludeApplications)

        if (($excludeApps -contains $appIdentifier) -or ($excludeApps -contains 'All')) {
            return $false
        }
        if (($includeApps -contains $appIdentifier) -or ($includeApps -contains 'All')) {
            return $true
        }
        return $false
    }

    hidden [string]SummarizeEffectiveControlsForCoverage([array]$policies) {
        if ($null -eq $policies -or $policies.Count -eq 0) {
            return "None"
        }

        foreach ($p_block in $policies) {
            if ($null -ne $p_block.GrantControls -and (@($p_block.GrantControls.BuiltInControls) -contains 'block')) {
                return "Blocked (by '$($p_block.DisplayName)')"
            }
        }

        $allControls = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $operators = [System.Collections.Generic.List[string]]::new()

        foreach ($p_grant in $policies) {
            if ($null -ne $p_grant.GrantControls -and $null -ne $p_grant.GrantControls.BuiltInControls) {
                $p_grant.GrantControls.BuiltInControls | ForEach-Object { $allControls.Add($_) }
                if ($p_grant.GrantControls.Operator) {$operators.Add($p_grant.GrantControls.Operator)}
            }
        }

        if ($allControls.Count -eq 0) {
            return "Grant (No specific built-in controls listed)"
        }

        $controlsString = ($allControls | Sort-Object) -join ", "
        $operatorSummary = if ($operators.Count -gt 0) { " (Operators involved: $($operators -join ', '))" } else { "" }
        return "Requires: $controlsString$operatorSummary"
    }

    [hashtable]AnalyzePolicyCoverage([array]$criticalUsers, [array]$criticalApplications) {
        Write-Verbose "Analyzing policy coverage..."
        if ($null -eq $this.AllPolicies -or $this.AllPolicies.Count -eq 0) {
            Write-Warning "No policies loaded into AdvancedPolicyAnalyzer. Cannot perform coverage analysis."
            return @{ UserCoverage = @(); ApplicationCoverage = @() }
        }

        $activePolicies = $this.AllPolicies | Where-Object { $_.State -eq 'enabled' -or $_.State -eq 'enabledForReportingButNotEnforced' }
        if ($activePolicies.Count -eq 0) {
            Write-Warning "No active (enabled or enabledForReportingButNotEnforced) policies found. Coverage will be zero."
        }

        $userCoverageResults = [System.Collections.Generic.List[object]]::new()
        $applicationCoverageResults = [System.Collections.Generic.List[object]]::new()

        if ($null -ne $criticalUsers) {
            foreach ($userUPN in $criticalUsers) {
                if ([string]::IsNullOrWhiteSpace($userUPN)) { continue }
                Write-Verbose "Analyzing coverage for user: $userUPN"
                $applicablePoliciesToCurrentUser = [System.Collections.Generic.List[object]]::new()
                foreach ($policy in $activePolicies) {
                    if ($this.DoesPolicyApplyToUser($policy, $userUPN)) {
                        $applicablePoliciesToCurrentUser.Add($policy)
                    }
                }
                $isCovered = $applicablePoliciesToCurrentUser.Count -gt 0
                $policyCount = $applicablePoliciesToCurrentUser.Count
                $controlsSummary = $this.SummarizeEffectiveControlsForCoverage($applicablePoliciesToCurrentUser.ToArray())

                $userCoverageResults.Add([PSCustomObject]@{
                    UserUPN                  = $userUPN
                    IsCovered                = $isCovered
                    AppliedPolicyCount       = $policyCount
                    EffectiveControlsSummary = $controlsSummary
                    Policies                 = ($applicablePoliciesToCurrentUser.DisplayName -join "; ")
                })
            }
        }

        if ($null -ne $criticalApplications) {
            foreach ($appIdentifier in $criticalApplications) {
                if ([string]::IsNullOrWhiteSpace($appIdentifier)) { continue }
                Write-Verbose "Analyzing coverage for application: $appIdentifier"
                $applicablePoliciesToCurrentApp = [System.Collections.Generic.List[object]]::new()
                foreach ($policy in $activePolicies) {
                    if ($this.DoesPolicyApplyToApplication($policy, $appIdentifier)) {
                        $applicablePoliciesToCurrentApp.Add($policy)
                    }
                }
                $isCovered = $applicablePoliciesToCurrentApp.Count -gt 0
                $policyCount = $applicablePoliciesToCurrentApp.Count
                $controlsSummary = $this.SummarizeEffectiveControlsForCoverage($applicablePoliciesToCurrentApp.ToArray())

                $applicationCoverageResults.Add([PSCustomObject]@{
                    Application              = $appIdentifier
                    IsCovered                = $isCovered
                    AppliedPolicyCount       = $policyCount
                    EffectiveControlsSummary = $controlsSummary
                    Policies                 = ($applicablePoliciesToCurrentApp.DisplayName -join "; ")
                })
            }
        }

        Write-Verbose "Policy coverage analysis complete."
        return @{
            UserCoverage = $userCoverageResults.ToArray()
            ApplicationCoverage = $applicationCoverageResults.ToArray()
        }
    }

    [hashtable]GeneratePolicyChangeImpactAnalysis([string]$policyId, [datetime]$changeDate) {
        # INPUT: Specific Policy ID that changed, and the date/time of change. Uses $this.SignInLogs, $this.AuditLogs.
        # FUNCTIONALITY: (Highly conceptual for a placeholder)
        # 1. Analyze sign-in patterns (success/failure rates, MFA challenges) for users/apps affected by the policy
        #    BEFORE and AFTER the $changeDate.
        # 2. Correlate with audit logs for that specific policy change.
        # 3. Attempt to quantify or describe the impact of the policy change.
        # EXAMPLE OUTPUT:
        # @{
        #     PolicyName = "Name of Policy ID"
        #     ChangeDescription = "Details from Audit Log"
        #     ImpactSummary = "Sign-in failures for affected scope increased by X% after change."
        # }
        Write-Warning "'GeneratePolicyChangeImpactAnalysis' is not fully implemented. Returns conceptual data."
        return @{ PolicyId = $policyId; ImpactSummary = "Conceptual analysis placeholder." }
    }
}
