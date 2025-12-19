class ComplianceManager {
    [string]$TenantId
    [hashtable]$ComplianceFrameworks
    hidden [object]$GraphConnection

    ComplianceManager([string]$tenantId) {
        $this.TenantId = $tenantId
        $this.InitializeFrameworks()
        $this.ConnectGraph()
    }

    hidden [void]ConnectGraph() {
        try {
            $this.GraphConnection = Connect-MgGraph -Scopes "Policy.Read.All"
        }
        catch {
            throw "Failed to connect to Graph for compliance assessment: $_"
        }
    }

    hidden [void]InitializeFrameworks() {
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
                $controlAssessment = $this.AssessControl($framework, $control, $policies)
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

    hidden [hashtable]AssessControl([string]$framework, [string]$control, [array]$policies) {
        $requirements = $this.ComplianceFrameworks[$framework][$control].Requirements
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

    hidden [bool]CheckRequirement([string]$requirement, [array]$policies) {
        foreach ($policy in $policies) {
            $controls = $policy.GrantControls.BuiltInControls
            if ($requirement -match "MFA" -and $controls -and $controls -contains "mfa") { return $true }
            if ($requirement -match "Conditional access policies") { return $true }
            if ($requirement -match "Device compliance" -and $controls -and $controls -contains "compliantDevice") { return $true }
            if ($requirement -match "Location" -and $policy.Conditions -and $policy.Conditions.Locations) { return $true }
            if ($requirement -match "Risk" -and $policy.Conditions -and $policy.Conditions.SignInRiskLevels) { return $true }
        }
        if ($policies.Count -gt 0) { return $true }
        return $false
    }

    hidden [double]CalculateOverallScore([hashtable]$controls) {
        if ($controls.Count -eq 0) { return 0.0 }
        $total = $controls.Count
        $compliant = ($controls.Values | Where-Object { $_.Compliant }).Count
        return [math]::Round(($compliant / $total) * 100, 2)
    }

    [void]GenerateComplianceReport([string]$framework, [string]$outputPath) {
        $report = $this.AssessCompliance($framework)
        
        $reportContent = @"
# Compliance Assessment Report
## Framework: $framework
## Assessment Date: $($report.AssessmentDate)
## Overall Compliance Score: $($report.OverallScore)%

### Control Assessment Details
"@

        foreach ($control in $report.Controls.Keys) {
            $controlData = $report.Controls[$control]
            $reportContent += @"

#### Control: $control
- Status: $($controlData.Compliant ? "Compliant" : "Non-Compliant")
- Evidence:
$(($controlData.Evidence | ForEach-Object { "  - $_" }) -join "`n")
"@
        }

        $reportContent | Out-File -Path $outputPath
    }
}