Describe "ComplianceManager" {
    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot "../../src/modules/compliance/compliance_manager.ps1") -Force -ErrorAction Stop
        Mock Connect-MgGraph { return @{} }
        $script:policies = @(
            [pscustomobject]@{
                DisplayName = "TestPolicy"
                GrantControls = @{ BuiltInControls = @("mfa", "compliantDevice") }
                Conditions = @{ Locations = @("loc1"); SignInRiskLevels = @("medium") }
            }
        )
        Mock Get-MgIdentityConditionalAccessPolicy { return $script:policies }
        $script:manager = [ComplianceManager]::new("tenant")
    }

    It "Should score ISO27001 controls as compliant with matching controls" {
        $report = $script:manager.AssessCompliance('ISO27001')
        $report.OverallScore | Should -BeGreaterThan 0
        ($report.Controls.Values | Where-Object { -not $_.Compliant }).Count | Should -Be 0
    }
}
