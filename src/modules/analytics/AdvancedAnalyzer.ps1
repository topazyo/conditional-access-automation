# src/modules/analytics/advanced_analyzer.ps1
# Module for Advanced Conditional Access Policy Analytics

class AdvancedPolicyAnalyzer {
    # Hidden properties for potential data sources or configurations
    hidden [array]$AllPolicies
    hidden [array]$SignInLogs
    hidden [array]$AuditLogs
    hidden [hashtable]$UserGroupMembershipMap # Stores UPN -> array of Group IDs

    AdvancedPolicyAnalyzer([array]$policies, [array]$signInLogs, [array]$auditLogs, [hashtable]$userGroupMap = $null) {
        if ($null -eq $policies -or $policies.Count -eq 0) {
            Write-Warning "AdvancedPolicyAnalyzer initialized with no policies. Most analytics functions will not yield results."
        } elseif ($null -eq $policies[0].PSObject.Properties['Id'] -or $null -eq $policies[0].PSObject.Properties['DisplayName']) {
            Write-Warning "AdvancedPolicyAnalyzer initialized with an array that does not appear to contain valid policy objects (missing Id or DisplayName). Analytics may fail."
        }
        $this.AllPolicies = @($policies) # Ensure it's an array
        $this.SignInLogs = $signInLogs
        $this.AuditLogs = $auditLogs
        $this.UserGroupMembershipMap = $userGroupMap

        Write-Verbose "AdvancedPolicyAnalyzer initialized with $($this.AllPolicies.Count) policies."
        if ($null -ne $this.UserGroupMembershipMap) {
            Write-Verbose "User group membership map provided with $($this.UserGroupMembershipMap.Count) entries."
        } else {
            Write-Verbose "No user group membership map provided."
        }
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
                # Pass the UserGroupMembershipMap to the overlap checkers if they are enhanced to use it.
                # For now, assuming they use their existing logic.
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
        if ($null -eq $usersA -and $null -eq $usersB) { return @{ OverlapType = 'None'; Description = "Both user conditions are null." } }
        if ($null -eq $usersA) { return @{ OverlapType = 'Unknown'; Description = "Policy A user conditions are null, Policy B is not." } }
        if ($null -eq $usersB) { return @{ OverlapType = 'Unknown'; Description = "Policy B user conditions are null, Policy A is not." } }

        $normalize = { param($items) if($null -eq $items){@()} else {@($items)} }

        $incUsersA = $normalize.Invoke($usersA.IncludeUsers)
        $excUsersA = $normalize.Invoke($usersA.ExcludeUsers)
        $incGroupsA = $normalize.Invoke($usersA.IncludeGroups)
        $excGroupsA = $normalize.Invoke($usersA.ExcludeGroups)
        $incGuestsA = $normalize.Invoke($usersA.IncludeGuestsOrExternalUsers)

        $incUsersB = $normalize.Invoke($usersB.IncludeUsers)
        $excUsersB = $normalize.Invoke($usersB.ExcludeUsers)
        $incGroupsB = $normalize.Invoke($usersB.IncludeGroups)
        $excGroupsB = $normalize.Invoke($usersB.ExcludeGroups)
        $incGuestsB = $normalize.Invoke($usersB.IncludeGuestsOrExternalUsers)

        $isAAllUsers = ($incUsersA -contains 'All') -or ($incGuestsA -contains 'all')
        $isBAllUsers = ($incUsersB -contains 'All') -or ($incGuestsB -contains 'all')
        $desc = ""

        if ($isAAllUsers -and $isBAllUsers) {
            $desc = "Both policies target 'All Users'."
            if (($excUsersA -join ';') -ne ($excUsersB -join ';') -or ($excGroupsA -join ';') -ne ($excGroupsB -join ';')) {
                $desc += " Exclusions differ: Policy A excludes Users:($($excUsersA -join ',')),Groups:($($excGroupsA -join ',')). Policy B excludes Users:($($excUsersB -join ',')),Groups:($($excGroupsB -join ','))."
            } else {
                $desc += " Exclusions are identical or both empty."
            }
            return @{ OverlapType = 'Full (All Users vs All Users)'; Description = $desc }
        }

        if ($isAAllUsers) {
            $bUsersNotExcludedByA = $incUsersB | Where-Object { $_ -notin $excUsersA }
            $bGroupsNotExcludedByA = $incGroupsB | Where-Object { $_ -notin $excGroupsA }
            if ($bUsersNotExcludedByA.Count -gt 0 -or $bGroupsNotExcludedByA.Count -gt 0) {
                return @{ OverlapType = 'Subset (All Users vs Specific)'; Description = "Policy A (All Users) likely contains Policy B's specific scope. Policy A excludes Users:($($excUsersA -join ',')),Groups:($($excGroupsA -join ','))." }
            } else {
                 return @{ OverlapType = 'None'; Description = "Policy A (All Users) excludes all specific users/groups targeted by Policy B." }
            }
        }

        if ($isBAllUsers) {
            $aUsersNotExcludedByB = $incUsersA | Where-Object { $_ -notin $excUsersB }
            $aGroupsNotExcludedByB = $incGroupsA | Where-Object { $_ -notin $excGroupsB }
            if ($aUsersNotExcludedByB.Count -gt 0 -or $aGroupsNotExcludedByB.Count -gt 0) {
                return @{ OverlapType = 'Subset (Specific vs All Users)'; Description = "Policy B (All Users) likely contains Policy A's specific scope. Policy B excludes Users:($($excUsersB -join ',')),Groups:($($excGroupsB -join ','))." }
            } else {
                return @{ OverlapType = 'None'; Description = "Policy B (All Users) excludes all specific users/groups targeted by Policy A." }
            }
        }

        $effectiveIncUsersA = $incUsersA | Where-Object { $_ -notin $excUsersA }
        $effectiveIncGroupsA = $incGroupsA | Where-Object { $_ -notin $excGroupsA }
        $effectiveIncUsersB = $incUsersB | Where-Object { $_ -notin $excUsersB }
        $effectiveIncGroupsB = $incGroupsB | Where-Object { $_ -notin $excGroupsB }

        $userIntersection = $effectiveIncUsersA | Where-Object { $_ -in $effectiveIncUsersB }
        $groupIntersection = $effectiveIncGroupsA | Where-Object { $_ -in $effectiveIncGroupsB }

        if ($userIntersection.Count -gt 0 -or $groupIntersection.Count -gt 0) {
            $desc = "Partial overlap. Common Users: $($userIntersection -join ', '). Common Groups: $($groupIntersection -join ', ')."
            return @{ OverlapType = 'Partial'; Description = $desc }
        }

        return @{ OverlapType = 'None'; Description = "No common users or groups found after considering direct exclusions." }
    }

    hidden [hashtable]CompareApplicationConditionOverlap([object]$appsA, [object]$appsB) {
        if ($null -eq $appsA -and $null -eq $appsB) { return @{ OverlapType = 'None'; Description = "Both application conditions are null." } }
        if ($null -eq $appsA) { return @{ OverlapType = 'Unknown'; Description = "Policy A application conditions are null, Policy B is not." } }
        if ($null -eq $appsB) { return @{ OverlapType = 'Unknown'; Description = "Policy B application conditions are null, Policy A is not." } }

        $normalize = { param($items) if($null -eq $items){@()} else {@($items)} }

        $incAppsA = $normalize.Invoke($appsA.IncludeApplications)
        $excAppsA = $normalize.Invoke($appsA.ExcludeApplications)
        $actionsA = $normalize.Invoke($appsA.IncludeUserActions)

        $incAppsB = $normalize.Invoke($appsB.IncludeApplications)
        $excAppsB = $normalize.Invoke($appsB.ExcludeApplications)
        $actionsB = $normalize.Invoke($appsB.IncludeUserActions)

        $isAAllApps = $incAppsA -contains 'All'
        $isBAllApps = $incAppsB -contains 'All'
        $desc = ""

        if ($isAAllApps -and $isBAllApps) {
            $desc = "Both policies target 'All Applications'."
            if (($excAppsA -join ';') -ne ($excAppsB -join ';')) {
                $desc += " Exclusions differ: Policy A excludes ($($excAppsA -join ', ')), Policy B excludes ($($excAppsB -join ', '))."
            } else {
                 $desc += " Exclusions are identical or both empty."
            }
            return @{ OverlapType = 'Full (All Apps vs All Apps)'; Description = $desc }
        }

        if ($isAAllApps) {
            $bAppsNotExcludedByA = $incAppsB | Where-Object { $_ -notin $excAppsA -and $_ -ne 'None' }
            if ($bAppsNotExcludedByA.Count -gt 0) {
                return @{ OverlapType = 'Subset (All Apps vs Specific)'; Description = "Policy A (All Apps) contains Policy B's specific app scope. Policy A excludes ($($excAppsA -join ', '))." }
            } else {
                 return @{ OverlapType = 'None'; Description = "Policy A (All Apps) excludes all specific applications targeted by Policy B." }
            }
        }
        if ($isBAllApps) {
            $aAppsNotExcludedByB = $incAppsA | Where-Object { $_ -notin $excAppsB -and $_ -ne 'None' }
            if ($aAppsNotExcludedByB.Count -gt 0) {
                return @{ OverlapType = 'Subset (Specific vs All Apps)'; Description = "Policy B (All Apps) contains Policy A's specific app scope. Policy B excludes ($($excAppsB -join ', '))." }
            } else {
                return @{ OverlapType = 'None'; Description = "Policy B (All Apps) excludes all specific applications targeted by Policy A." }
            }
        }

        $effectiveIncAppsA = $incAppsA | Where-Object { $_ -notin $excAppsA }
        $effectiveIncAppsB = $incAppsB | Where-Object { $_ -notin $excAppsB }

        $appIntersection = $effectiveIncAppsA | Where-Object { $_ -in $effectiveIncAppsB -and $_ -ne 'None' }

        if ($appIntersection.Count -gt 0) {
            $desc = "Partial overlap on applications: $($appIntersection -join ', ')."
            if (($actionsA -join ';') -ne ($actionsB -join ';')) {
                $desc += " User Actions differ (A: $($actionsA -join ', '), B: $($actionsB -join ', '))."
            } elseif ($actionsA.Count -gt 0) {
                 $desc += " User Actions are similar/identical: $($actionsA -join ', ')."
            }
            return @{ OverlapType = 'Partial'; Description = $desc }
        }

        if ($incAppsA.Count -eq 0 -and $actionsA.Count -gt 0 -and $incAppsB.Count -eq 0 -and $actionsB.Count -gt 0) {
            $actionIntersection = $actionsA | Where-Object { $_ -in $actionsB }
            if ($actionIntersection.Count -gt 0) {
                return @{ OverlapType = 'Partial'; Description = "Partial overlap on User Actions only: $($actionIntersection -join ', ')." }
            }
        }

        return @{ OverlapType = 'None'; Description = "No common applications found after considering exclusions." }
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

    hidden [bool]DoesPolicyApplyToUser([object]$policy, [string]$userUPN, [array]$userGroupIdsForContext = $null) {
        if ($null -eq $policy -or $null -eq $policy.Conditions -or $null -eq $policy.Conditions.Users) { return $false }

        $usersCondition = $policy.Conditions.Users
        $normalize = { param($items) if($null -eq $items){@()} else {@($items)} }

        $includeUsers = $normalize.Invoke($usersCondition.IncludeUsers)
        $excludeUsers = $normalize.Invoke($usersCondition.ExcludeUsers)
        $includeGroups = $normalize.Invoke($usersCondition.IncludeGroups)
        $excludeGroups = $normalize.Invoke($usersCondition.ExcludeGroups)
        # $includeGuests = $normalize.Invoke($usersCondition.IncludeGuestsOrExternalUsers) # Not fully utilized in this simplified version yet

        # 1. Direct Exclusions by UPN or 'All'
        if (($excludeUsers -contains $userUPN) -or ($excludeUsers -contains 'All')) {
            return $false
        }

        # 2. Direct Inclusions by UPN or 'All'
        if (($includeUsers -contains $userUPN) -or ($includeUsers -contains 'All')) {
            # If 'All' users are included, need to check if this specific user is part of group exclusions
            if ($includeUsers -contains 'All') {
                if ($null -ne $userGroupIdsForContext -and $userGroupIdsForContext.Count -gt 0) {
                    $isExcludedByGroup = $excludeGroups | Where-Object { $_ -in $userGroupIdsForContext } | Select-Object -First 1
                    if ($null -ne $isExcludedByGroup) {
                        return $false # User is in an excluded group, even if 'All Users' is included
                    }
                }
            }
            return $true # Direct UPN match or 'All Users' (and not excluded by group if 'All Users')
        }

        # 3. Group Membership Logic
        if ($includeGroups.Count -gt 0) {
            if ($null -ne $userGroupIdsForContext -and $userGroupIdsForContext.Count -gt 0) {
                $intersectingIncludeGroups = $includeGroups | Where-Object { $_ -in $userGroupIdsForContext }
                if ($intersectingIncludeGroups.Count -gt 0) {
                    # User is in at least one included group. Now check if they are also in an excluded group for this policy.
                    $effectivelyAppliedGroup = $intersectingIncludeGroups | Where-Object { $_ -notin $excludeGroups } | Select-Object -First 1
                    if ($null -ne $effectivelyAppliedGroup) {
                        return $true # User is in an included group that is not also in an excluded group
                    }
                }
            } else {
                # Policy targets groups, but no group context for the user was provided.
                # Cannot definitively say if it applies or not based on groups.
                # Do not return true here; if no other condition matches, it won't apply.
                # Warning is good, but can be noisy if called repeatedly. Consider how often to warn.
                # For this iteration, the warning is outside this specific helper if $this.UserGroupMembershipMap is null for the user.
            }
        }

        # TODO: Add IncludeGuestsOrExternalUsers logic if $userUPN matches guest patterns, considering ExcludeGuestsOrExternalUsers
        # For now, this simplified version relies on UPN/Group matching.

        return $false # Default if no inclusion criteria met or if excluded
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
             return @{ UserCoverage = @(); ApplicationCoverage = @() } # Return empty if no active policies
        }

        $userCoverageResults = [System.Collections.Generic.List[object]]::new()
        $applicationCoverageResults = [System.Collections.Generic.List[object]]::new()

        # User Coverage
        if ($null -ne $criticalUsers) {
            foreach ($userUPN in $criticalUsers) {
                if ([string]::IsNullOrWhiteSpace($userUPN)) { continue }
                Write-Verbose "Analyzing coverage for user: $userUPN"

                $currentUserGroupIds = $null
                if ($null -ne $this.UserGroupMembershipMap -and $this.UserGroupMembershipMap.ContainsKey($userUPN)) {
                    $currentUserGroupIds = @($this.UserGroupMembershipMap[$userUPN])
                    Write-Verbose "Found group membership context for user '$userUPN' (Groups: $($currentUserGroupIds.Count))."
                } else {
                    Write-Verbose "No pre-loaded group membership context found for user '$userUPN'. Group-based policy checks will be limited."
                }

                $applicablePoliciesToCurrentUser = [System.Collections.Generic.List[object]]::new()
                foreach ($policy in $activePolicies) {
                    if ($this.DoesPolicyApplyToUser($policy, $userUPN, $currentUserGroupIds)) {
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

        # Application Coverage (remains unchanged by this subtask)
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

    [hashtable]GeneratePolicyChangeImpactAnalysis([string]$policyId, [datetime]$changeDate, [int]$daysWindow = 7) {
        Write-Verbose "Generating policy change impact analysis for policy ID '$policyId', change date '$changeDate'."
        if (($null -eq $this.SignInLogs -or $this.SignInLogs.Count -eq 0) -or
            ($null -eq $this.AuditLogs -or $this.AuditLogs.Count -eq 0)) {
            Write-Warning "SignInLogs or AuditLogs not available/populated in AdvancedPolicyAnalyzer. Cannot perform change impact analysis."
            return @{ PolicyId = $policyId; Error = "SignInLogs or AuditLogs not available." }
        }

        $policyFromState = $this.AllPolicies | Where-Object {$_.Id -eq $policyId} | Select-Object -First 1
        $policyDisplayName = if ($null -ne $policyFromState) { $policyFromState.DisplayName } else { "Unknown (ID: $policyId)" }

        # Fetch Change Description from Audit Logs
        $auditLogEntry = $this.AuditLogs |
            Where-Object { $_.TargetResources -ne $null -and ($_.TargetResources | Where-Object {$_.Id -eq $policyId}).Count -gt 0 -and $_.OperationType -match "policy" } |
            Sort-Object ActivityDateTime -Descending |
            Where-Object { $_.ActivityDateTime -le $changeDate } |
            Select-Object -First 1

        $actor = "Unknown"
        if ($null -ne $auditLogEntry.InitiatedBy) {
            if ($null -ne $auditLogEntry.InitiatedBy.User -and -not [string]::IsNullOrEmpty($auditLogEntry.InitiatedBy.User.UserPrincipalName)) {
                $actor = $auditLogEntry.InitiatedBy.User.UserPrincipalName
            } elseif ($null -ne $auditLogEntry.InitiatedBy.App -and -not [string]::IsNullOrEmpty($auditLogEntry.InitiatedBy.App.DisplayName)) {
                $actor = "Application: $($auditLogEntry.InitiatedBy.App.DisplayName)"
            }
        }
        $changeDescription = if ($auditLogEntry) { "Audit: '$($auditLogEntry.ActivityDisplayName)' by $actor at $($auditLogEntry.ActivityDateTime.ToString('o'))" } else { "No specific audit log entry found for this policy ID around the change date." }

        # Define Time Windows
        $beforeStartDate = $changeDate.AddDays(-$daysWindow).Date # Start of day
        $beforeEndDate = $changeDate.Date.AddSeconds(-1)          # End of day before change (e.g., 23:59:59)
        $afterStartDate = $changeDate.Date                       # Start of day of change
        $afterEndDate = $changeDate.AddDays($daysWindow).Date.AddDays(1).AddSeconds(-1) # End of day, $daysWindow after

        Write-Verbose "Analysis window: Before ($($beforeStartDate.ToString('o')) - $($beforeEndDate.ToString('o'))), After ($($afterStartDate.ToString('o')) - $($afterEndDate.ToString('o')))"

        # Filter Sign-in Logs where the specific policy was applied
        $relevantSignInLogs = $this.SignInLogs | Where-Object {
            $_.AppliedConditionalAccessPolicies -ne $null -and ($_.AppliedConditionalAccessPolicies | Where-Object {$_.Id -eq $policyId}).Count -gt 0
        }

        if ($relevantSignInLogs.Count -eq 0) {
            Write-Warning "No sign-in logs found where policy '$policyDisplayName' (Id: $policyId) was applied. Cannot analyze impact from processed sign-ins."
            return @{
                PolicyName = $policyDisplayName; PolicyId = $policyId; ChangeDate = $changeDate.ToString("o");
                ChangeAuditEvent = $changeDescription; AnalysisWindowDays = $daysWindow;
                ImpactSummary = "No sign-in logs found where this policy was applied within the loaded SignInLogs."
            }
        } else {
             Write-Verbose "Found $($relevantSignInLogs.Count) relevant sign-in logs for policy '$policyDisplayName'."
        }

        $beforeLogs = $relevantSignInLogs | Where-Object { $_.CreatedDateTime -ge $beforeStartDate -and $_.CreatedDateTime -le $beforeEndDate }
        $afterLogs = $relevantSignInLogs | Where-Object { $_.CreatedDateTime -ge $afterStartDate -and $_.CreatedDateTime -le $afterEndDate }
        Write-Verbose "Sign-ins before change: $($beforeLogs.Count), Sign-ins after change: $($afterLogs.Count)"

        $beforeMetrics = $this.GetMetricsFromLogs($beforeLogs, $policyId)
        $afterMetrics = $this.GetMetricsFromLogs($afterLogs, $policyId)

        # Summarize Impact
        $impactSummary = ""
        if ($beforeMetrics.TotalSignIns -eq 0 -and $afterMetrics.TotalSignIns -eq 0) {
            $impactSummary = "No sign-in activity (where this policy applied) found in the 'before' or 'after' periods within the provided logs."
        } elseif ($beforeMetrics.TotalSignIns -eq 0) {
            $impactSummary = "No sign-in activity (where this policy applied) found in the 'before' period. After change: Success Rate $($afterMetrics.SuccessRate)%, MFA by this policy: $($afterMetrics.MfaChallengesByThisPolicy)."
        } elseif ($afterMetrics.TotalSignIns -eq 0) {
            $impactSummary = "No sign-in activity (where this policy applied) found in the 'after' period. Before change: Success Rate $($beforeMetrics.SuccessRate)%, MFA by this policy: $($beforeMetrics.MfaChallengesByThisPolicy)."
        } else {
            $impactSummary = "Sign-in success rate changed from $($beforeMetrics.SuccessRate)% (of $($beforeMetrics.TotalSignIns) sign-ins) to $($afterMetrics.SuccessRate)% (of $($afterMetrics.TotalSignIns) sign-ins). "
            $impactSummary += "MFA challenges specifically by this policy changed from $($beforeMetrics.MfaChallengesByThisPolicy) to $($afterMetrics.MfaChallengesByThisPolicy)."
        }

        return @{
            PolicyName = $policyDisplayName
            PolicyId = $policyId
            ChangeDate = $changeDate.ToString("o") # Use ISO 8601 for consistency
            ChangeAuditEvent = $changeDescription
            AnalysisWindowDays = $daysWindow
            MetricsTimeWindow = @{
                BeforePeriod_Start = $beforeStartDate.ToString("yyyy-MM-dd"); BeforePeriod_End = $beforeEndDate.ToString("yyyy-MM-dd")
                AfterPeriod_Start = $afterStartDate.ToString("yyyy-MM-dd"); AfterPeriod_End = $afterEndDate.ToString("yyyy-MM-dd")
            }
            BeforePeriodMetrics = $beforeMetrics
            AfterPeriodMetrics = $afterMetrics
            ImpactSummary = $impactSummary
            Note = "Impact analysis is based on sign-ins where this policy ID was explicitly listed in AppliedConditionalAccessPolicies."
        }
    }

    hidden [hashtable]GetMetricsFromLogs([array]$logs, [string]$policyIdForMfaCheck) {
        if ($null -eq $logs) { $logs = @() } # Ensure it's an array if null is passed
        $totalSignIns = $logs.Count
        $successfulSignIns = ($logs | Where-Object {$_.Status.ErrorCode -eq 0}).Count
        $failedSignIns = $totalSignIns - $successfulSignIns
        $successRate = if ($totalSignIns -gt 0) { [math]::Round(($successfulSignIns / $totalSignIns) * 100, 2) } else { 0 }

        $mfaChallengesByThisPolicy = 0
        if ($null -ne $logs) {
            $mfaChallengesByThisPolicy = ($logs | Where-Object {
                $_.AppliedConditionalAccessPolicies -ne $null -and `
                ($_.AppliedConditionalAccessPolicies | Where-Object {$_.Id -eq $policyIdForMfaCheck -and ($_.EnforcedGrantControls -contains 'mfa' -or $_.EnforcedGrantControls -contains 'multiFactorAuthentication')}).Count -gt 0
            }).Count
        }

        return @{
            TotalSignIns = $totalSignIns
            SuccessfulSignIns = $successfulSignIns
            FailedSignIns = $failedSignIns
            SuccessRate = $successRate
            MfaChallengesByThisPolicy = $mfaChallengesByThisPolicy
        }
    }
}
