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
}