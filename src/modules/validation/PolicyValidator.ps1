class PolicyValidator {
    [hashtable]$ValidationRules
    [array]$ValidationResults

    PolicyValidator() {
        $this.InitializeValidationRules()
        $this.ValidationResults = @()
    }

    # Method to validate an array of policy definitions
    [hashtable]ValidatePolicies([array]$policyDefinitions) {
        $allErrors = [System.Collections.Generic.List[string]]::new()
        $allWarnings = [System.Collections.Generic.List[string]]::new()
        $allRecommendations = [System.Collections.Generic.List[string]]::new()
        $overallIsValid = $true # Assume all are valid until an error is found

        if ($null -eq $policyDefinitions -or $policyDefinitions.Count -eq 0) {
            Write-Warning "No policy definitions provided to ValidatePolicies."
            return @{
                HasErrors                 = $false # No errors because nothing was processed to be invalid
                TotalPoliciesProcessed    = 0
                TotalErrorsFound          = 0
                TotalWarningsFound        = 0
                TotalRecommendationsFound = 0
                AllErrorMessages          = @()
                AllWarningMessages        = @()
                AllRecommendationMessages = @()
            }
        }

        Write-Verbose "Validating $($policyDefinitions.Count) policy definitions."

        foreach ($policyDef in $policyDefinitions) {
            $policyDisplayNameForError = if ($null -ne $policyDef -and $policyDef.PSObject.Properties.Name.Contains('DisplayName') -and -not [string]::IsNullOrEmpty($policyDef.DisplayName)) {
                "'$($policyDef.DisplayName)'"
            } else {
                "'Unnamed Policy (index $($policyDefinitions.IndexOf($policyDef)))'"
            }

            try {
                # Note: The current PolicyValidator class does not have its own ValidatePolicyDefinition method.
                # That method is part of ConditionalAccessPolicyManager.
                # Here, we directly call ValidatePolicy which performs all checks.
                # If fundamental checks were in a separate ValidatePolicyDefinition within this class,
                # we would call it first and catch its specific errors.
                # For now, ValidatePolicy itself will populate errors if any are found.

                if ($null -eq $policyDef -or ($policyDef -isnot [hashtable] -and $policyDef -isnot [pscustomobject])) {
                    $allErrors.Add("Policy definition $policyDisplayNameForError is null or not a valid object. Skipping.")
                    $overallIsValid = $false
                    continue
                }

                $singlePolicyResult = $this.ValidatePolicy($policyDef) # This is the existing method

                if (-not $singlePolicyResult.IsValid) {
                    $overallIsValid = $false
                }
                # Prefix messages with policy display name for better context in aggregate report
                $singlePolicyResult.Errors | ForEach-Object { $allErrors.Add("Policy $policyDisplayNameForError Error: $_") }
                $singlePolicyResult.Warnings | ForEach-Object { $allWarnings.Add("Policy $policyDisplayNameForError Warning: $_") }
                $singlePolicyResult.Recommendations | ForEach-Object { $allRecommendations.Add("Policy $policyDisplayNameForError Recommendation: $_") }
            }
            catch {
                # This catch block would handle unexpected errors from within ValidatePolicy itself,
                # not from a separate ValidatePolicyDefinition if it were called here and threw.
                $overallIsValid = $false
                $allErrors.Add("Policy $policyDisplayNameForError failed validation with an unexpected exception: $($_.Exception.Message)")
            }
        }

        return @{
            HasErrors                 = -not $overallIsValid
            TotalPoliciesProcessed    = $policyDefinitions.Count
            TotalErrorsFound          = $allErrors.Count
            TotalWarningsFound        = $allWarnings.Count
            TotalRecommendationsFound = $allRecommendations.Count
            AllErrorMessages          = $allErrors.ToArray()
            AllWarningMessages        = $allWarnings.ToArray()
            AllRecommendationMessages = $allRecommendations.ToArray()
        }
    }

    hidden [void]InitializeValidationRules() {
        $this.ValidationRules = @{
            RequiredProperties = @(
                "displayName",
                "state",
                "conditions",
                "grantControls"
            )
            
            Conditions = @{
                MaxUserScope = 1000
                RestrictedApplications = @(
                    "Microsoft Graph Explorer",
                    "Legacy Authentication Clients"
                )
                RequiredPlatformStates = @(
                    "enabled",
                    "disabled",
                    "configurationRequired"
                )
            }
            
            SecurityBaseline = @{
                RequireMFA = $true
                BlockLegacyAuth = $true
                RequireCompliantDevice = $true
                MaxSessionDuration = 8
            }
        }
    }

    [hashtable]ValidatePolicy([hashtable]$policy) {
        $results = @{
            IsValid = $true
            Errors = @()
            Warnings = @()
            Recommendations = @()
        }

        # Check required properties
        foreach ($prop in $this.ValidationRules.RequiredProperties) {
            if (-not $policy.ContainsKey($prop)) {
                $results.IsValid = $false
                $results.Errors += "Missing required property: $prop"
            }
        }

        # Validate user scope
        if ($policy.conditions.users.includeUsers -contains "All") {
            $results.Warnings += "Policy applies to all users - consider scope restriction"
        }

        # Validate applications
        foreach ($app in $policy.conditions.applications.includeApplications) {
            if ($app -in $this.ValidationRules.Conditions.RestrictedApplications) {
                $results.Errors += "Restricted application included: $app"
                $results.IsValid = $false
            }
        }

        # Validate MaxUserScope
        if ($null -ne $policy.conditions.users -and $policy.conditions.users.includeUsers -notcontains "All") {
            $userScopeCount = 0
            if ($null -ne $policy.conditions.users.includeUsers) {
                $userScopeCount += $policy.conditions.users.includeUsers.Count
            }
            if ($null -ne $policy.conditions.users.includeGroups) {
                $userScopeCount += $policy.conditions.users.includeGroups.Count
            }
            if ($userScopeCount -gt $this.ValidationRules.Conditions.MaxUserScope) {
                $results.Warnings += "Policy targets a large number of individual users/groups ($userScopeCount entries), exceeding the recommended maximum of $($this.ValidationRules.Conditions.MaxUserScope). Consider using 'All users' with exclusions or broader groups if appropriate."
            }
        }

        # Validate RequiredPlatformStates
        if ($policy.conditions.ContainsKey("platforms") -and $null -ne $policy.conditions.platforms) {
            $includePlatforms = $policy.conditions.platforms.includePlatforms
            $excludePlatforms = $policy.conditions.platforms.excludePlatforms

            if (($null -eq $includePlatforms -or $includePlatforms.Count -eq 0) -and `
                ($null -eq $excludePlatforms -or $excludePlatforms.Count -eq 0)) {
                $results.Warnings += "Policy defines a 'platforms' condition block but does not specify any platforms to include or exclude. This may lead to unintended behavior or indicate an incomplete policy configuration for platforms."
            }
        }

        # Validate security baseline
        if ($this.ValidationRules.SecurityBaseline.RequireMFA) {
            if (($null -eq $policy.grantControls) -or ($null -eq $policy.grantControls.builtInControls) -or (-not ($policy.grantControls.builtInControls -contains "mfa"))) {
                $results.Recommendations += "Consider adding MFA requirement"
            }
        }

        # Validate SecurityBaseline.BlockLegacyAuth
        if ($this.ValidationRules.SecurityBaseline.BlockLegacyAuth -eq $true) {
            if ($null -ne $policy.conditions.clientAppTypes -and $policy.conditions.clientAppTypes -contains 'other') {
                $results.Warnings += "This policy targets/allows legacy authentication clients ('other' in clientAppTypes). It is recommended to block legacy authentication across the tenant via a separate, dedicated policy, as it's a significant security risk."
            }
            else {
                # This specific policy doesn't allow legacy auth, but recommend a general policy.
                # Ensure clientAppTypes is checked to avoid recommending this if the policy *does* target 'other'
                if ($null -eq $policy.conditions.clientAppTypes -or $policy.conditions.clientAppTypes -notcontains 'other') {
                    $results.Recommendations += "Consider implementing a dedicated policy to explicitly block legacy authentication ('other' clientAppTypes) if not already in place tenant-wide."
                }
            }
        }

        # Validate SecurityBaseline.RequireCompliantDevice
        if ($this.ValidationRules.SecurityBaseline.RequireCompliantDevice -eq $true) {
            if (($null -eq $policy.grantControls) -or ($null -eq $policy.grantControls.builtInControls) -or `
                (-not ($policy.grantControls.builtInControls -contains "compliantDevice") -and `
                 -not ($policy.grantControls.builtInControls -contains "block"))) {
                $results.Recommendations += "Consider requiring a compliant device as a grant control for this policy to enhance security, unless it's intentionally a more permissive policy or access is blocked."
            }
        }

        # Validate session controls
        if ($policy.sessionControls.signInFrequency.value -gt $this.ValidationRules.SecurityBaseline.MaxSessionDuration) {
            $results.Warnings += "Session duration exceeds recommended maximum"
        }

        # Check for potential conflicts
        $conflicts = $this.CheckPolicyConflicts($policy)
        if ($conflicts.Count -gt 0) {
            $results.Warnings += "Potential policy conflicts detected: $($conflicts -join '; ')"
        }

        return $results
    }

    [array]CheckPolicyConflicts([hashtable]$policy) {
        $conflicts = @()
        
        # Get existing policies
        $existingPolicies = Get-MgIdentityConditionalAccessPolicy
        
        foreach ($existingPolicy in $existingPolicies) {
            if ($this.DetectConflict($policy, $existingPolicy)) {
                $conflicts += "Conflict with policy: $($existingPolicy.DisplayName)"
            }
        }
        
        return $conflicts
    }

    hidden [bool]DetectConflict([hashtable]$newPolicy, [object]$existingPolicy) {
        # Check for user overlap
        $userOverlap = $this.CheckUserOverlap(
            $newPolicy.conditions.users,
            $existingPolicy.Conditions.Users
        )
        
        # Check for application overlap
        $appOverlap = $this.CheckApplicationOverlap(
            $newPolicy.conditions.applications,
            $existingPolicy.Conditions.Applications
        )
        
        # Check for contradicting controls
        $controlConflict = $this.CheckControlConflict(
            $newPolicy.grantControls,
            $existingPolicy.GrantControls
        )
        
        return ($userOverlap -and $appOverlap -and $controlConflict)
    }

    hidden [bool]CheckUserOverlap($newUsers, $existingUsers) {
        if ($newUsers.includeUsers -contains "All" -or $existingUsers.IncludeUsers -contains "All") {
            return $true
        }
        
        $overlap = Compare-Object `
            $newUsers.includeUsers `
            $existingUsers.IncludeUsers `
            -IncludeEqual `
            -ExcludeDifferent
            
        return $overlap.Count -gt 0
    }

    # Enhanced implementation to check for application overlap.
    hidden [bool]CheckApplicationOverlap([hashtable]$newApplications, [object]$existingApplications) {
        # Normalize "All" applications GUID for comparison
        $allAppsGuid = "00000000-0000-0000-0000-000000000000" # Placeholder for actual "All" applications ID if it's a GUID
        # Graph API might return 'All', a specific GUID for "All Client Apps", or an empty array for includeApplications and rely on includeUserActions.
        # For this logic, we'll assume 'All' string or a known GUID signifies all applications.

        $newIncludes = @($newApplications.includeApplications | ForEach-Object { $_ -replace "'", "" }) # Sanitize if needed
        $newExcludes = @($newApplications.excludeApplications | ForEach-Object { $_ -replace "'", "" })
        $newActions = @($newApplications.includeUserActions | ForEach-Object { $_ -replace "'", "" })

        $existingIncludes = @($existingApplications.IncludeApplications | ForEach-Object { $_ -replace "'", "" })
        $existingExcludes = @($existingApplications.ExcludeApplications | ForEach-Object { $_ -replace "'", "" })
        $existingActions = @($existingApplications.IncludeUserActions | ForEach-Object { $_ -replace "'", "" })

        $newIsAllApps = $newIncludes -contains "All" -or $newIncludes -contains $allAppsGuid
        $existingIsAllApps = $existingIncludes -contains "All" -or $existingIncludes -contains $allAppsGuid

        $appOverlapDetected = $false

        if ($newIsAllApps -and $existingIsAllApps) {
            Write-Verbose "AppOverlap: Both policies target 'All' applications."
            $appOverlapDetected = $true
        } elseif ($newIsAllApps) {
            # New is "All", existing is specific. Overlap if any of existing's includes are not in new's excludes.
            foreach ($app in $existingIncludes) {
                if ($app -notin $newExcludes) {
                    Write-Verbose "AppOverlap: New targets 'All', existing targets '$app' which is not excluded by new."
                    $appOverlapDetected = $true
                    break
                }
            }
        } elseif ($existingIsAllApps) {
            # Existing is "All", new is specific. Overlap if any of new's includes are not in existing's excludes.
            foreach ($app in $newIncludes) {
                if ($app -notin $existingExcludes) {
                    Write-Verbose "AppOverlap: Existing targets 'All', new targets '$app' which is not excluded by existing."
                    $appOverlapDetected = $true
                    break
                }
            }
        } else {
            # Both are specific lists of applications.
            foreach ($newApp in $newIncludes) {
                if (($newApp -in $existingIncludes) -and ($newApp -notin $newExcludes) -and ($newApp -notin $existingExcludes)) {
                    Write-Verbose "AppOverlap: Specific app '$newApp' is included in both policies and not excluded by either."
                    $appOverlapDetected = $true
                    break
                }
            }
        }

        if (-not $appOverlapDetected) {
            # If no direct application ID overlap, consider user actions if one policy is "All Apps" and the other has specific user actions,
            # or if both have user actions but no app IDs. This part can be complex.
            # For this version, if app IDs don't overlap, we assume no overlap for simplicity unless both target 'All' user actions.
            # A more refined check would be if one is All Apps and has user actions that intersect with the other policy's user actions (even if other has specific apps).
            if (($newActions -contains "All" -or $newActions -contains "all") -and ($existingActions -contains "All" -or $existingActions -contains "all") ) {
                 # This case is if app IDs didn't overlap but both policies have "All" user actions, which is a broad overlap.
                 # This might be too simplistic if apps were very specific and disjoint.
                 # However, if $appOverlapDetected is false, it means apps were disjoint or one/both were empty.
                 # If both $newIncludes and $existingIncludes are empty, then user actions become primary.
                if (($newIncludes.Count -eq 0 -or $newIncludes[0] -eq 'None') -and ($existingIncludes.Count -eq 0 -or $existingIncludes[0] -eq 'None')){
                     Write-Verbose "AppOverlap: No specific apps, but both policies target 'All' user actions."
                     $appOverlapDetected = $true
                }
            }
             # If one targets all apps and has user actions, and the other has specific apps but matching user actions.
             # This is getting too complex for this iteration, focusing on app ID based overlap first.
        }


        # If application overlap is detected, then check user actions for further refinement (optional for this version, consider it overlap if apps overlap)
        if ($appOverlapDetected) {
            # At this point, application IDs are considered overlapping.
            # We can refine by checking user actions, but the prompt stated:
            # "If application IDs overlap but user actions do not intersect...this specific subtask should still consider it an application overlap"
            # So, we don't need to make $appOverlapDetected false based on user actions if it's already true.
            # However, we can log the user action situation.

            $newHasAllActions = $newActions -contains "All" -or $newActions -contains "all"
            $existingHasAllActions = $existingActions -contains "All" -or $existingActions -contains "all"

            if ($newHasAllActions -and $existingHasAllActions) {
                Write-Verbose "UserAction SubCheck: Both policies apply to 'All' user actions for the overlapping apps."
            } elseif ($newHasAllActions -and $existingActions.Count -gt 0) {
                Write-Verbose "UserAction SubCheck: New policy 'All' actions, Existing has specific actions for overlapping apps."
            } elseif ($existingHasAllActions -and $newActions.Count -gt 0) {
                Write-Verbose "UserAction SubCheck: Existing policy 'All' actions, New has specific actions for overlapping apps."
            } elseif ($newActions.Count -gt 0 -and $existingActions.Count -gt 0) {
                $commonActions = Compare-Object $newActions $existingActions -IncludeEqual -ExcludeDifferent
                if ($commonActions.Count -gt 0) {
                    Write-Verbose "UserAction SubCheck: Common specific user actions found for overlapping apps: $($commonActions | Select-Object -ExpandProperty InputObject -Join ', ')"
                } else {
                    Write-Verbose "UserAction SubCheck: Specific user actions for overlapping apps do not intersect."
                }
            }
            return $true # As per requirement, if apps overlap, it's an overlap.
        }

        Write-Verbose "No significant application overlap detected by enhanced check."
        return $false
    }

    # Enhanced implementation for control conflict detection.
    hidden [bool]CheckControlConflict([hashtable]$newGrantControls, [object]$existingGrantControls) {
        # Ensure grant controls and builtInControls are available for comparison
        $newControls = $newGrantControls.builtInControls
        $existingControls = $existingGrantControls.BuiltInControls # Note: Property name from Graph might be .BuiltInControls

        # If either policy has no specific grant controls defined (e.g., it's purely conditional), no conflict.
        if (($null -eq $newControls -or $newControls.Count -eq 0) -or `
            ($null -eq $existingControls -or $existingControls.Count -eq 0)) {
            Write-Verbose "ControlConflict: One or both policies have no defined built-in grant controls. No conflict."
            return $false
        }

        $newIsBlock = $newControls -contains "block"
        $existingIsBlock = $existingControls -contains "block"

        # Case 1: Both policies block. This is not a conflict; they agree.
        if ($newIsBlock -and $existingIsBlock) {
            Write-Verbose "ControlConflict: Both policies enforce 'block'. No conflict."
            return $false
        }

        # Case 2: One policy blocks, the other grants/requires (i.e., does not block and has controls). This is a conflict.
        if ($newIsBlock -and (-not $existingIsBlock -and $existingControls.Count -gt 0) ) {
            Write-Warning "ControlConflict: New policy 'blocks' while existing policy grants/requires specific controls (e.g., $($existingControls -join ', ')). Potential conflict."
            return $true
        }
        if ($existingIsBlock -and (-not $newIsBlock -and $newControls.Count -gt 0) ) {
            Write-Warning "ControlConflict: Existing policy 'blocks' while new policy grants/requires specific controls (e.g., $($newControls -join ', ')). Potential conflict."
            return $true
        }

        # Case 3: Neither policy blocks. Both grant/require controls.
        # In CA, multiple matching policies that grant access result in the user needing to satisfy the union of controls.
        # This is generally not considered a "conflict" but rather a cumulative requirement.
        # Example: Policy A requires MFA. Policy B requires Compliant Device. User needs both.
        # A true *impossibility* (e.g., must be MFA AND must NOT be MFA) is not typical with standard builtInControls.
        if (-not $newIsBlock -and -not $existingIsBlock) {
            Write-Warning "ControlConflict: Neither policy blocks. Controls are assumed cumulative or alternative (e.g., MFA OR CompliantDevice if Operator is OR). Detailed grant-vs-grant impossibility analysis is not performed. No direct 'block' conflict."
            return $false
        }

        # Default case, should ideally not be reached if logic above is complete.
        return $false
    }
}