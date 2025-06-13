class RiskAssessor {
    hidden [hashtable]$RiskFactors
    hidden [hashtable]$RiskWeights

    static [RiskAssessor] NewFromFile([string]$configFilePath) {
        Write-Verbose "Attempting to load RiskAssessor configuration from file: $configFilePath"
        if (-not (Test-Path -Path $configFilePath -PathType Leaf)) {
            throw "RiskAssessor configuration file not found: $configFilePath"
        }

        $configJson = Get-Content -Path $configFilePath -Raw -ErrorAction Stop
        $config = $null
        try {
            $config = $configJson | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "Failed to parse JSON from RiskAssessor configuration file '$configFilePath'. Error: $($_.Exception.Message)"
        }

        if ($null -eq $config) { # Should be caught by try-catch if ConvertFrom-Json fails, but as a safeguard.
            throw "Parsed configuration from '$configFilePath' is null."
        }

        if (-not $config.PSObject.Properties.Name.Contains('riskFactors') -or $config.riskFactors -isnot [hashtable]) {
            throw "Invalid RiskAssessor config from '$configFilePath': 'riskFactors' property is missing or not a valid object/hashtable."
        }
        if (-not $config.PSObject.Properties.Name.Contains('riskWeights') -or $config.riskWeights -isnot [hashtable]) {
            throw "Invalid RiskAssessor config from '$configFilePath': 'riskWeights' property is missing or not a valid object/hashtable."
        }

        Write-Verbose "Successfully loaded and validated risk model from '$configFilePath'."
        return [RiskAssessor]::new($config.riskFactors, $config.riskWeights)
    }

    # Constructor now accepts custom risk factors and weights.
    # If custom values are provided, they will be merged with/override the defaults.
    RiskAssessor([hashtable]$customRiskFactors, [hashtable]$customRiskWeights) {
        # Initialize with default factors and weights first
        $this.InitializeDefaultRiskFactorsAndWeights()

        # Merge custom risk factors if provided
        if ($null -ne $customRiskFactors) {
            Write-Verbose "Validating and applying custom risk factors."
            foreach ($factorName in $customRiskFactors.Keys) {
                $factorValue = $customRiskFactors[$factorName]

                # Validate structure: if overriding a default factor that is a hashtable, custom one must also be a hashtable
                if ($this.RiskFactors.ContainsKey($factorName) -and $this.RiskFactors[$factorName] -is [hashtable]) {
                    if ($factorValue -isnot [hashtable]) {
                        Write-Warning "Custom risk factor '$factorName' is expected to be a hashtable to override existing default factor structure, but it is a '$($factorValue.GetType().Name)'. Skipping this custom factor."
                        continue # Skip this invalid custom factor
                    }
                    # If both are hashtables, merge them (shallow merge for sub-hashtable)
                    Write-Verbose "Merging sub-factors for '$factorName'."
                    foreach ($subKey in $factorValue.Keys) {
                        # Optional: Add type checks for sub-factor values if they are expected to be numeric
                        $this.RiskFactors[$factorName][$subKey] = $factorValue[$subKey]
                    }
                } else {
                    # Otherwise, it's a new factor or overriding a non-hashtable one (if any)
                    # Basic validation: if the factorValue itself is a hashtable, ensure its sub-values are numeric (common for risk factors)
                    if ($factorValue -is [hashtable]) {
                        foreach ($subKeyValue in $factorValue.Values) { # Renamed from $subKeyVal
                            if ($subKeyValue -isnot [double] -and $subKeyValue -isnot [int]) {
                                Write-Warning "Value '$subKeyValue' for sub-key under custom factor '$factorName' is not numeric. Ensure all terminal risk factor values are numbers."
                                # Depending on strictness, could skip this subKey or the whole factor.
                            }
                        }
                    } elseif($factorValue -isnot [double] -and $factorValue -isnot [int] -and $this.RiskFactors.ContainsKey($factorName)) {
                         # If overriding a known non-hashtable factor, it should be numeric
                         Write-Warning "Custom risk factor '$factorName' (which is not a category/hashtable) has a non-numeric value '$factorValue'. Skipping."
                         continue
                    }
                    $this.RiskFactors[$factorName] = $factorValue
                }
            }
        }

        # Merge custom risk weights if provided (weights are typically flat key-value)
        if ($null -ne $customRiskWeights) {
            Write-Verbose "Validating and applying custom risk weights."
            foreach ($weightName in $customRiskWeights.Keys) {
                $weightValue = $customRiskWeights[$weightName]
                $isNumeric = $true
                try {
                    [double]$weightValue | Out-Null
                } catch {
                    $isNumeric = $false
                }

                if (-not $isNumeric) {
                    Write-Warning "Custom risk weight '$weightName' value '$($weightValue)' is not numeric. Skipping this custom weight."
                    continue # Skip this invalid custom weight
                }
                $this.RiskWeights[$weightName] = [double]$weightValue # Store as double
            }
        }
    }

    # Initializes the default risk factors and weights.
    # Called by the constructor before applying any custom configurations.
    hidden [void]InitializeDefaultRiskFactorsAndWeights() {
        $this.RiskFactors = @{
            PolicyScope = @{
                AllUsers = 0.8
                SpecificGroups = 0.4
                Individual = 0.2
            }
            AuthenticationStrength = @{
                SingleFactor = 0.9
                MFA = 0.3
                Passwordless = 0.1
            }
            ApplicationScope = @{
                AllApps = 0.7
                CriticalApps = 0.5
                NonCriticalApps = 0.2
            }
            LocationContext = @{
                AnyLocation = 0.6
                TrustedLocationsOnly = 0.2
                SpecificCountries = 0.4
            }
        }

        $this.RiskWeights = @{
            PolicyScope = 0.4
            AuthenticationStrength = 0.3
            ApplicationScope = 0.2
            LocationContext = 0.1
        }
    }

    [double]CalculatePolicyRisk([hashtable]$policy) {
        $riskScore = 0.0

        # Assess policy scope
        $scopeRisk = if ($policy.Conditions.Users.IncludeUsers -contains "All") {
            $this.RiskFactors.PolicyScope.AllUsers
        }
        elseif ($policy.Conditions.Users.IncludeGroups) {
            $this.RiskFactors.PolicyScope.SpecificGroups
        }
        else {
            $this.RiskFactors.PolicyScope.Individual
        }
        $riskScore += $scopeRisk * $this.RiskWeights.PolicyScope

        # Assess authentication strength
        $authRisk = if ($policy.GrantControls.BuiltInControls -contains "passwordless") {
            $this.RiskFactors.AuthenticationStrength.Passwordless
        }
        elseif ($policy.GrantControls.BuiltInControls -contains "mfa") {
            $this.RiskFactors.AuthenticationStrength.MFA
        }
        else {
            $this.RiskFactors.AuthenticationStrength.SingleFactor
        }
        $riskScore += $authRisk * $this.RiskWeights.AuthenticationStrength

        return $riskScore
    }

    [hashtable]GenerateRiskReport([array]$policies) {
        $report = @{
            HighRiskPolicies = @()
            MediumRiskPolicies = @()
            LowRiskPolicies = @()
            OverallRiskScore = 0.0
            Recommendations = @()
        }

        foreach ($policy in $policies) {
            $riskScore = $this.CalculatePolicyRisk($policy)
            
            switch ($riskScore) {
                { $_ -ge 0.7 } {
                    $report.HighRiskPolicies += @{
                        PolicyName = $policy.DisplayName
                        RiskScore = $riskScore
                        Recommendations = $this.GenerateRecommendations($policy)
                    }
                }
                { $_ -ge 0.4 } {
                    $report.MediumRiskPolicies += @{
                        PolicyName = $policy.DisplayName
                        RiskScore = $riskScore
                        Recommendations = $this.GenerateRecommendations($policy)
                    }
                }
                default {
                    $report.LowRiskPolicies += @{
                        PolicyName = $policy.DisplayName
                        RiskScore = $riskScore
                    }
                }
            }
        }

        $report.OverallRiskScore = ($policies | ForEach-Object { $this.CalculatePolicyRisk($_) } | Measure-Object -Average).Average
        return $report
    }

    hidden [array]GenerateRecommendations([hashtable]$policy) {
        $recommendations = [System.Collections.Generic.List[string]]::new()

        # Ensure policy and conditions objects are not null
        if ($null -eq $policy -or $null -eq $policy.Conditions) {
            $recommendations.Add("Policy object or conditions are null, cannot generate recommendations.")
            return $recommendations.ToArray()
        }

        # 1. User Scope Recommendations
        if ($null -ne $policy.Conditions.Users) {
            $users = $policy.Conditions.Users
            if ($users.IncludeUsers -contains "All" -and ($null -eq $users.ExcludeUsers -or $users.ExcludeUsers.Count -eq 0)) {
                $recommendations.Add("Policy applies to 'All users' without exclusions. Refine scope to specific user groups or add targeted exclusions if 'All users' is too broad.")
            }
            # Graph API uses IncludeGuestsOrExternalUsers which is an array of strings like 'internalGuest', 'externalGuest', 'serviceProvider'.
            # If this array is populated, it means guest/external users are explicitly included.
            if ($null -ne $users.IncludeGuestsOrExternalUsers -and $users.IncludeGuestsOrExternalUsers.Count -gt 0) {
                 if (($users.IncludeGuestsOrExternalUsers -contains "all") -or ($users.IncludeGuestsOrExternalUsers -contains "guestsOrExternalUsers")) { # Heuristic for broad guest inclusion
                    $recommendations.Add("Policy explicitly includes all or a broad category of guests/external users. Review if this broad access for external identities is intended and necessary for all included resources.")
                 } else {
                    $recommendations.Add("Policy targets specific types of guests/external users ('$($users.IncludeGuestsOrExternalUsers -join "', '")'). Ensure this scope is appropriate.")
                 }
            }
        }

        # 2. Application Scope Recommendations
        if ($null -ne $policy.Conditions.Applications) {
            $apps = $policy.Conditions.Applications
            if ($apps.IncludeApplications -contains "All" -and ($null -eq $apps.ExcludeApplications -or $apps.ExcludeApplications.Count -eq 0)) {
                $recommendations.Add("Policy applies to 'All applications' without exclusions. Consider scoping to specific applications or application groups to limit impact and apply least privilege.")
            }
        }
        if ($null -ne $policy.Conditions.ClientAppTypes -and $policy.Conditions.ClientAppTypes -contains 'other') {
            $recommendations.Add("Policy allows/targets legacy authentication (clientAppTypes includes 'other'). Block legacy authentication protocols as they are a significant security risk and do not support modern authentication methods like MFA.")
        }

        # 3. Grant Control Recommendations
        if ($null -ne $policy.GrantControls) {
            $grantControls = $policy.GrantControls.BuiltInControls
            $operator = $policy.GrantControls.Operator

            if ($null -eq $grantControls -or $grantControls.Count -eq 0) {
                 $recommendations.Add("Policy has no grant controls. Access will be allowed without any additional requirements if conditions are met. Ensure this is intended.")
            } else {
                if (-not ($grantControls -contains "mfa") -and -not ($grantControls -contains "block")) {
                    $recommendations.Add("Policy does not enforce MFA. Require MFA for enhanced security, especially if sensitive applications or broad user scopes are targeted.")
                }
                if (-not ($grantControls -contains "compliantDevice") -and -not ($grantControls -contains "domainJoinedDevice") -and -not ($grantControls -contains "block")) {
                    $recommendations.Add("Policy does not require device compliance or Hybrid Azure AD join. Consider adding device-based trust requirements to strengthen access controls.")
                }
                if ($operator -eq 'OR' -and $grantControls.Count -gt 1 -and (($grantControls -contains "mfa") -or ($grantControls -contains "compliantDevice") -or ($grantControls -contains "passwordlessMfa"))) {
                     $recommendations.Add("Policy uses 'OR' for multiple grant controls (e.g., '$($grantControls -join "', '")'). This provides flexibility, but ensure this is intended versus requiring all listed controls (using 'AND') if a higher security posture is desired.")
                }
            }
        } else {
            $recommendations.Add("Policy has no grant controls defined. Access will be allowed without any additional requirements if conditions are met. This is highly insecure unless specifically intended for very limited scenarios.")
        }

        # 4. Session Control Recommendations
        if ($null -ne $policy.SessionControls) {
            $sessionControls = $policy.SessionControls
            if ($null -eq $sessionControls.SignInFrequency -or ($null -ne $sessionControls.SignInFrequency -and $sessionControls.SignInFrequency.Value -gt 24 -and ($sessionControls.SignInFrequency.Type -eq "hours" -or $sessionControls.SignInFrequency.Type -eq "days" ))) {
                 # More nuanced check for days vs hours
                $isLongDuration = $false
                if ($null -ne $sessionControls.SignInFrequency) {
                    if ($sessionControls.SignInFrequency.Type -eq "days" -and $sessionControls.SignInFrequency.Value -gt 1) {$isLongDuration = $true}
                    if ($sessionControls.SignInFrequency.Type -eq "hours" -and $sessionControls.SignInFrequency.Value -gt 24) {$isLongDuration = $true}
                } else { # Null SignInFrequency means it's not set
                    $isLongDuration = $true
                }
                if($isLongDuration){
                    $recommendations.Add("Sign-in frequency is not configured or is set to a long duration. Configure a shorter reauthentication period (e.g., 8-24 hours for sensitive apps, 1-7 days for others) to enhance security posture.")
                }
            }
            if ($null -ne $sessionControls.PersistentBrowser -and $sessionControls.PersistentBrowser.IsEnabled -eq $true) {
                $recommendations.Add("Persistent browser session (Keep me signed in) is enabled. Evaluate if this is necessary, as it can increase risk on shared or potentially compromised devices. Prefer disabling if not essential or scope it narrowly.")
            }
        } else {
             $recommendations.Add("Session controls (like Sign-in Frequency or Persistent Browser) are not configured. Consider defining these to manage session lifetimes and reauthentication requirements.")
        }

        # 5. Condition-Specific Recommendations (Risk Levels)
        if ($null -ne $policy.Conditions) {
            if ($null -eq $policy.Conditions.SignInRiskLevels -or $policy.Conditions.SignInRiskLevels.Count -eq 0) {
                $recommendations.Add("Policy does not leverage sign-in risk conditions. Implement dynamic policies that respond to real-time sign-in risk (e.g., require MFA or block for high-risk sign-ins).")
            }
            if ($null -eq $policy.Conditions.UserRiskLevels -or $policy.Conditions.UserRiskLevels.Count -eq 0) {
                $recommendations.Add("Policy does not leverage user risk conditions. Implement user risk-based policies for proactive protection of identities flagged as compromised (e.g., require password change or block).")
            }
        }

        # Fallback for old location condition check, if relevant properties are still used
        if ($null -ne $policy.Conditions.Locations -and $policy.Conditions.Locations.IncludeLocations -contains "All") {
            $recommendations.Add("Policy location condition includes 'All' locations without apparent trusted location exclusions. If trusted IPs/locations are defined, ensure they are used effectively for exclusion or specific inclusion policies.")
        }

        return $recommendations.ToArray()
    }
}