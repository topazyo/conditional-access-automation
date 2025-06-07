class PolicyValidator {
    [hashtable]$ValidationRules
    [array]$ValidationResults

    PolicyValidator() {
        $this.InitializeValidationRules()
        $this.ValidationResults = @()
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

        # Validate security baseline
        if ($this.ValidationRules.SecurityBaseline.RequireMFA) {
            if (-not ($policy.grantControls.builtInControls -contains "mfa")) {
                $results.Recommendations += "Consider adding MFA requirement"
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