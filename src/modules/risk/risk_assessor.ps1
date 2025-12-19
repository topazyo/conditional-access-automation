class RiskAssessor {
    hidden [hashtable]$RiskFactors
    hidden [hashtable]$RiskWeights

    RiskAssessor() {
        $this.InitializeRiskFactors()
    }

    hidden [void]InitializeRiskFactors() {
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
        $recommendations = @()

        if ($policy.Conditions.Users.IncludeUsers -contains "All") {
            $recommendations += "Consider scoping policy to specific groups instead of all users"
        }

        if (-not ($policy.GrantControls.BuiltInControls -contains "mfa")) {
            $recommendations += "Implement MFA requirement for stronger authentication"
        }

        if ($policy.Conditions.Locations.IncludeLocations -contains "All") {
            $recommendations += "Consider restricting access to specific locations or trusted IPs"
        }

        return $recommendations
    }
}