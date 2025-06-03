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

    # Basic implementation to check for application overlap.
    # This is a simplified check.
    hidden [bool]CheckApplicationOverlap([hashtable]$newApplications, [object]$existingApplications) {
        if (($null -eq $newApplications -or $null -eq $newApplications.includeApplications) -and
            ($null -eq $existingApplications -or $null -eq $existingApplications.IncludeApplications)) {
            return $false # No applications defined in either
        }

        # If one policy applies to "All" applications, and the other has any includes, it's an overlap.
        # Note: Graph API returns "All" as a specific GUID '00000000-0000-0000-0000-000000000000' or "None" for specific exclusions.
        # For simplicity, we'll check for "All" string if manually defined, or the known GUID.
        # A more robust check would use the specific GUIDs for "All" and "None".
        if (($newApplications.includeApplications -contains "All" -or $newApplications.includeApplications -contains "00000000-0000-0000-0000-000000000000") -and $existingApplications.IncludeApplications.Count -gt 0) {
            # Consider excluded apps if "All" is used. If new is "All" but excludes what existing includes, it might not be an overlap.
            # This basic version doesn't deeply check exclusions against "All".
            Write-Verbose "Overlap: New policy includes 'All' applications."
            return $true
        }
        if (($existingApplications.IncludeApplications -contains "All" -or $existingApplications.IncludeApplications -contains "00000000-0000-0000-0000-000000000000") -and $newApplications.includeApplications.Count -gt 0) {
            Write-Verbose "Overlap: Existing policy includes 'All' applications."
            return $true
        }

        # Check for common application IDs if neither is "All"
        if ($null -ne $newApplications.includeApplications -and $null -ne $existingApplications.IncludeApplications) {
            $commonApps = Compare-Object $newApplications.includeApplications $existingApplications.IncludeApplications -IncludeEqual -ExcludeDifferent
            if ($commonApps.Count -gt 0) {
                Write-Verbose "Overlap: Common applications found: $($commonApps | Select-Object -ExpandProperty InputObject -Join ', ')"
                return $true
            }
        }

        # Basic check for user actions if applications are not defined or don't overlap
        # This part is highly dependent on how user actions are structured and compared.
        # For now, if includeUserActions has 'All' in one and any action in another, consider it a potential overlap.
        if (($newApplications.includeUserActions -contains "All" -or $newApplications.includeUserActions -contains "all") -and $existingApplications.IncludeUserActions.Count -gt 0) {
             Write-Verbose "Overlap: New policy includes 'All' user actions."
            return $true
        }
         if (($existingApplications.IncludeUserActions -contains "All" -or $existingApplications.IncludeUserActions -contains "all") -and $newApplications.includeUserActions.Count -gt 0) {
             Write-Verbose "Overlap: Existing policy includes 'All' user actions."
            return $true
        }
        if($null -ne $newApplications.includeUserActions -and $null -ne $existingApplications.IncludeUserActions){
            $commonActions = Compare-Object $newApplications.includeUserActions $existingApplications.IncludeUserActions -IncludeEqual -ExcludeDifferent
            if ($commonActions.Count -gt 0) {
                Write-Verbose "Overlap: Common user actions found: $($commonActions | Select-Object -ExpandProperty InputObject -Join ', ')"
                return $true
            }
        }


        Write-Verbose "No direct application or user action overlap found by basic check."
        return $false
    }

    # Basic placeholder for control conflict detection.
    # True conflict detection is very complex.
    hidden [bool]CheckControlConflict([hashtable]$newGrantControls, [object]$existingGrantControls) {
        # If either is null or has no controls, no conflict based on grant controls alone.
        if ($null -eq $newGrantControls -or $null -eq $existingGrantControls) {
            return $false
        }

        # Simplistic: If one policy blocks and the other grants/requires something, it's a potential conflict.
        # This doesn't account for conditions.
        if (($newGrantControls.Operator -eq "Block" -and $existingGrantControls.Operator -ne "Block") -or `
            ($existingGrantControls.Operator -eq "Block" -and $newGrantControls.Operator -ne "Block")) {
            Write-Warning "Potential conflict: One policy blocks while the other grants/requires. Conditions are not fully analyzed here."
            return $true # This is a strong indicator of conflict if conditions align.
        }

        # If both are grant controls, e.g., one requires MFA and other requires Compliant Device.
        # This is typically not a conflict but a combination if conditions match.
        # A true conflict would be if grant controls are mutually exclusive for the same conditions,
        # which is rare with builtInControls but could happen with customControls.
        # For now, returning false as a safe default for non-block scenarios.
        Write-Warning "Sophisticated control conflict detection (e.g., mutually exclusive grant controls) is not fully implemented. Assuming no conflict for non-block scenarios."
        return $false
    }
}