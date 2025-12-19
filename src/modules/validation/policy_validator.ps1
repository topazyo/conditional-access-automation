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
        $includeUsers = $this.GetIncludeUsers($policy.conditions.users)
        if ($includeUsers -contains "All") {
            $results.Warnings += "Policy applies to all users - consider scope restriction"
        }

        # Validate applications
        foreach ($app in $this.GetIncludeApplications($policy.conditions.applications)) {
            if ($app -in $this.ValidationRules.Conditions.RestrictedApplications) {
                $results.Errors += "Restricted application included: $app"
                $results.IsValid = $false
            }
        }

        # Validate security baseline
        if ($this.ValidationRules.SecurityBaseline.RequireMFA) {
            if (-not ($this.GetBuiltInControls($policy.grantControls) -contains "mfa")) {
                $results.Recommendations += "Consider adding MFA requirement"
            }
        }

        # Validate session controls
        if ($policy.sessionControls -and $policy.sessionControls.signInFrequency) {
            if ($policy.sessionControls.signInFrequency.value -gt $this.ValidationRules.SecurityBaseline.MaxSessionDuration) {
                $results.Warnings += "Session duration exceeds recommended maximum"
            }
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
        $newInclude = $this.GetIncludeUsers($newUsers)
        $existingInclude = $this.GetIncludeUsers($existingUsers)
        if ($newInclude -contains "All" -or $existingInclude -contains "All") {
            return $true
        }
        
        $overlap = Compare-Object `
            $newInclude `
            $existingInclude `
            -IncludeEqual `
            -ExcludeDifferent
            
        return $overlap.Count -gt 0
    }

    hidden [bool]CheckApplicationOverlap($newApps, $existingApps) {
        if (-not $newApps -or -not $existingApps) { return $false }
        $newInclude = $this.GetIncludeApplications($newApps)
        $existingInclude = $this.GetIncludeApplications($existingApps)
        if ($newInclude -contains "All" -or $existingInclude -contains "All") { return $true }

        $overlap = Compare-Object `
            $newInclude `
            $existingInclude `
            -IncludeEqual `
            -ExcludeDifferent

        return $overlap.Count -gt 0
    }

    hidden [bool]CheckControlConflict($newControls, $existingControls) {
        if (-not $newControls -or -not $existingControls) { return $false }

        $newBuiltIn = $this.GetBuiltInControls($newControls)
        $existingBuiltIn = $this.GetBuiltInControls($existingControls)

        if (-not $newBuiltIn -or -not $existingBuiltIn) { return $false }

        # Basic conflict: both target same users/apps and have differing operators with overlapping controls
        $overlap = Compare-Object `
            $newBuiltIn `
            $existingBuiltIn `
            -IncludeEqual `
            -ExcludeDifferent

        $operatorMismatch = $this.GetOperator($newControls) -and $this.GetOperator($existingControls) -and ($this.GetOperator($newControls) -ne $this.GetOperator($existingControls))

        return ($overlap.Count -gt 0 -and $operatorMismatch)
    }

    hidden [array]GetIncludeUsers($usersObj) {
        if (-not $usersObj) { return @() }
        if ($usersObj.PSObject.Properties.Match('IncludeUsers')) { return $usersObj.IncludeUsers }
        if ($usersObj.PSObject.Properties.Match('includeUsers')) { return $usersObj.includeUsers }
        return @()
    }

    hidden [array]GetIncludeApplications($appsObj) {
        if (-not $appsObj) { return @() }
        if ($appsObj.PSObject.Properties.Match('IncludeApplications')) { return $appsObj.IncludeApplications }
        if ($appsObj.PSObject.Properties.Match('includeApplications')) { return $appsObj.includeApplications }
        return @()
    }

    hidden [array]GetBuiltInControls($controlsObj) {
        if (-not $controlsObj) { return @() }
        if ($controlsObj.PSObject.Properties.Match('BuiltInControls')) { return $controlsObj.BuiltInControls }
        if ($controlsObj.PSObject.Properties.Match('builtInControls')) { return $controlsObj.builtInControls }
        return @()
    }

    hidden [string]GetOperator($controlsObj) {
        if (-not $controlsObj) { return $null }
        if ($controlsObj.PSObject.Properties.Match('Operator')) { return $controlsObj.Operator }
        if ($controlsObj.PSObject.Properties.Match('operator')) { return $controlsObj.operator }
        return $null
    }
}