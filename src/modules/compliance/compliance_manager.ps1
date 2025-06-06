class ComplianceManager {
    [string]$TenantId
    [hashtable]$ComplianceFrameworks
    hidden [object]$GraphConnection

    # Constructor now accepts custom compliance frameworks.
    # If custom frameworks are provided, they will be merged with/override the defaults.
    ComplianceManager([string]$tenantId, [hashtable]$customComplianceFrameworks) {
        $this.TenantId = $tenantId

        # Initialize with default frameworks first
        $this.InitializeDefaultFrameworks()

        # Merge custom compliance frameworks if provided
        if ($null -ne $customComplianceFrameworks) {
            Write-Verbose "Applying custom compliance frameworks."
            foreach ($frameworkName in $customComplianceFrameworks.Keys) {
                if ($this.ComplianceFrameworks.ContainsKey($frameworkName)) {
                    Write-Verbose "Overriding existing framework '$frameworkName' with custom definition."
                } else {
                    Write-Verbose "Adding new custom framework '$frameworkName'."
                }
                # This replaces the entire framework definition if it exists, or adds a new one.
                # Deep merging of individual controls within a framework would require more complex logic.
                $this.ComplianceFrameworks[$frameworkName] = $customComplianceFrameworks[$frameworkName]
            }
        }

        $this.ConnectGraph()
    }

    # Initializes the default compliance frameworks.
    # Called by the constructor before applying any custom configurations.
    hidden [void]InitializeDefaultFrameworks() {
        $this.ComplianceFrameworks = @{
            'ISO27001' = @{
                'A.9.4.1' = @{
                    Description = "Information access restriction"
                    Requirements = @(
                        "MFA enforcement",
                        "Conditional access policies",
                        "Just-in-time access"
                    )
                }
                'A.9.4.2' = @{
                    Description = "Secure log-on procedures"
                    Requirements = @(
                        "Risk-based authentication",
                        "Device compliance",
                        "Location-based access"
                    )
                }
            }
            'NIST80053' = @{
                'AC-2' = @{
                    Description = "Account Management"
                    Requirements = @(
                        "Automated account provisioning",
                        "Access reviews",
                        "Privilege management"
                    )
                }
            }
            'GDPR' = @{
                'Article32' = @{
                    Description = "Security of processing"
                    Requirements = @(
                        "Data access controls",
                        "Encryption",
                        "Access monitoring"
                    )
                }
            }
        }
    }

    [hashtable]AssessCompliance([string]$framework) {
        try {
            $policies = Get-MgIdentityConditionalAccessPolicy
            $complianceReport = @{
                Framework = $framework
                AssessmentDate = Get-Date
                Controls = @{}
                OverallScore = 0.0
                Gaps = @()
            }

            foreach ($control in $this.ComplianceFrameworks[$framework].Keys) {
                $controlAssessment = $this.AssessControl($control, $policies)
                $complianceReport.Controls[$control] = $controlAssessment
                
                if (-not $controlAssessment.Compliant) {
                    $complianceReport.Gaps += @{
                        Control = $control
                        Description = $controlAssessment.Description
                        Remediation = $controlAssessment.Remediation
                    }
                }
            }

            $complianceReport.OverallScore = $this.CalculateOverallScore($complianceReport.Controls)
            return $complianceReport
        }
        catch {
            Write-Error "Failed to assess compliance: $_"
            throw
        }
    }

    hidden [hashtable]AssessControl([string]$control, [array]$policies) {
        $requirements = $this.ComplianceFrameworks[$control].Requirements
        $assessment = @{
            Compliant = $true
            Description = ""
            Evidence = @()
            Remediation = @()
        }

        foreach ($req in $requirements) {
            $satisfied = $this.CheckRequirement($req, $policies)
            if (-not $satisfied) {
                $assessment.Compliant = $false
                $assessment.Remediation += "Implement $req"
            }
            else {
                $assessment.Evidence += "Requirement '$req' satisfied by policy"
            }
        }

        return $assessment
    }

    # Enhanced implementation to check if policies satisfy specific requirements.
    [bool]CheckRequirement([string]$requirement, [array]$policies) {
        Write-Verbose "Attempting to check requirement: '$($requirement)' against available policies."

        # Handle meta-requirement "Conditional access policies"
        if ($requirement -eq "Conditional access policies") {
            if ($policies.Count -gt 0) {
                Write-Verbose "Requirement 'Conditional access policies' satisfied as policies exist."
                return $true # True if any CA policies exist
            } else {
                Write-Verbose "Requirement 'Conditional access policies' not satisfied as no policies exist."
                return $false
            }
        }
        
        # Handle "Just-in-time access" - difficult to verify via CA policies alone
        if ($requirement -eq "Just-in-time access") {
            Write-Warning "Checking for 'Just-in-time access' is not fully supported by inspecting CA policies alone. This typically involves Azure AD PIM integration."
            return $false # Cannot confirm JIT from CA policies directly
        }

        # Iterate through each policy to check against the specific requirement
        foreach ($policy in $policies) {
            # Ensure the policy is enabled for it to be considered effective
            if ($policy.State -ne "enabled") {
                Write-Verbose "Skipping policy '$($policy.DisplayName)' as it is not enabled."
                continue
            }

            switch ($requirement) {
                "MFA enforcement" {
                    # Check if the policy requires MFA as a grant control
                    if ($policy.GrantControls -and
                        ($policy.GrantControls.Operator -eq 'OR' -or $policy.GrantControls.Operator -eq 'AND') -and
                        $policy.GrantControls.BuiltInControls -contains "mfa") {
                        Write-Verbose "Policy '$($policy.DisplayName)' satisfies 'MFA enforcement'."
                        return $true
                    }
                }
                "Device compliance" {
                    # Check if the policy requires a compliant device as a grant control
                    if ($policy.GrantControls -and
                        ($policy.GrantControls.Operator -eq 'OR' -or $policy.GrantControls.Operator -eq 'AND') -and
                        $policy.GrantControls.BuiltInControls -contains "compliantDevice") {
                        Write-Verbose "Policy '$($policy.DisplayName)' satisfies 'Device compliance'."
                        return $true
                    }
                }
                "Location-based access" {
                    # Check if the policy has specific locations included or excluded
                    # 'any' or 'all' might be represented by specific GUIDs or null/empty arrays depending on creation method.
                    # A simple check for non-empty IncludeLocations (not 'All') or any ExcludeLocations.
                    if ($policy.Conditions.Locations -and
                        (($policy.Conditions.Locations.IncludeLocations -ne $null -and $policy.Conditions.Locations.IncludeLocations.Count -gt 0 -and $policy.Conditions.Locations.IncludeLocations[0] -ne "All") -or # Specific include locations
                         ($policy.Conditions.Locations.ExcludeLocations -ne $null -and $policy.Conditions.Locations.ExcludeLocations.Count -gt 0))) { # Any exclude locations
                        Write-Verbose "Policy '$($policy.DisplayName)' satisfies 'Location-based access'."
                        return $true
                    }
                }
                "Risk-based authentication" {
                    # Check if the policy targets specific sign-in risk levels
                    # 'all' is not a valid Graph API value for risk levels, they are specific like 'high', 'medium', 'low', 'none'.
                    if ($policy.Conditions.SignInRiskLevels -ne $null -and $policy.Conditions.SignInRiskLevels.Count -gt 0) {
                         # Ensure it's not just 'none' if 'none' is considered not risk-based for this check.
                         # For this check, any specified risk level (high, medium, low) means it's risk-based.
                        if (!($policy.Conditions.SignInRiskLevels.Count -eq 1 -and $policy.Conditions.SignInRiskLevels[0] -eq "none")) {
                             Write-Verbose "Policy '$($policy.DisplayName)' satisfies 'Risk-based authentication'."
                             return $true
                        }
                    }
                }
                default {
                    # This case will be hit if the requirement string from the loop doesn't match a known check.
                    # The outer function will handle unknown requirements after the loop if no policy satisfies it.
                }
            }
        }

        # If the loop completes without returning true for a specific requirement, it means no policy satisfied it.
        # However, if the requirement itself was unknown from the start, this path shouldn't be hit due to the default switch.
        # This warning is for requirements that are known but no policy met them.
        if ($requirement -notin ("MFA enforcement", "Device compliance", "Location-based access", "Risk-based authentication", "Conditional access policies", "Just-in-time access")) {
             Write-Warning "Requirement '$($requirement)' is unknown or not specifically checked by the enhanced logic. Defaulting to false."
        } else {
            Write-Verbose "No enabled policy found satisfying requirement: '$($requirement)'."
        }
        return $false
    }

    # Calculates a simple percentage score based on how many controls are compliant.
    [double]CalculateOverallScore([hashtable]$controlsAssessment) {
        if ($null -eq $controlsAssessment -or $controlsAssessment.Count -eq 0) {
            return 0.0
        }
        $compliantCount = 0
        foreach ($controlKey in $controlsAssessment.Keys) {
            if ($controlsAssessment[$controlKey].Compliant) {
                $compliantCount++
            }
        }
        $score = ($compliantCount / $controlsAssessment.Count) * 100
        return [math]::Round($score, 2)
    }

    [void]GenerateComplianceReport([string]$framework, [string]$outputPath) {
        Write-Verbose "Generating compliance report for framework '$framework' to path '$outputPath'."
        $report = $this.AssessCompliance($framework) # This gets the detailed assessment data

        if ($null -eq $report) {
            Write-Error "Failed to assess compliance for framework '$framework'. Report generation aborted."
            return
        }

        $csvOutput = [System.Collections.Generic.List[PSCustomObject]]::new()

        if ($null -ne $report.Controls) {
            foreach ($controlEntry in $report.Controls.GetEnumerator()) {
                $controlID = $controlEntry.Name
                $controlData = $controlEntry.Value # This is the assessment for the control

                # Get the control definition from the framework
                $controlFrameworkDefinition = $null
                if ($this.ComplianceFrameworks.ContainsKey($framework) -and $this.ComplianceFrameworks[$framework].ContainsKey($controlID)) {
                    $controlFrameworkDefinition = $this.ComplianceFrameworks[$framework][$controlID]
                } else {
                    Write-Warning "Could not find framework definition for control ID '$controlID' in framework '$framework'."
                }

                $csvRow = [PSCustomObject]@{
                    Framework          = $framework
                    AssessmentDate     = $report.AssessmentDate.ToString("yyyy-MM-dd HH:mm:ss")
                    OverallScore       = [math]::Round($report.OverallScore, 2) # Ensure OverallScore is rounded
                    ControlID          = $controlID
                    ControlDescription = if ($null -ne $controlFrameworkDefinition) { $controlFrameworkDefinition.Description } else { "N/A" }
                    Compliant          = $controlData.Compliant
                    Evidence           = $controlData.Evidence -join "; " # Join array into a semi-colon separated string
                    RemediationSteps   = $controlData.Remediation -join "; " # Join array
                }
                $csvOutput.Add($csvRow)
            }
        } else {
            Write-Warning "No controls data found in the assessment report for framework '$framework'."
        }

        if ($csvOutput.Count -gt 0) {
            try {
                $csvOutput | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                Write-Host "Successfully generated CSV compliance report at '$outputPath'."
            }
            catch {
                Write-Error "Failed to export CSV report to '$outputPath'. Error: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "No data to write to CSV report for framework '$framework'. Report file not created."
        }
    }
}