Describe "ConditionalAccessPolicyManager" {
    BeforeAll {
        # Mock Graph API connection
        Mock Connect-MgGraph { return @{} }
        
        $manager = [ConditionalAccessPolicyManager]::new("test-tenant-id")
    }

    Context "Policy Deployment" {
        It "Should validate policy definition before deployment" {
            $invalidPolicy = @{
                DisplayName = "Test Policy"
                # Missing required properties
            }

            { $manager.DeployPolicy($invalidPolicy) } | Should -Throw
        }

        It "Should successfully deploy valid policy" {
            $validPolicy = @{
                DisplayName = "Test Policy"
                State = "enabled"
                Conditions = @{
                    Users = @{
                        IncludeUsers = @("group1")
                    }
                }
                GrantControls = @{
                    BuiltInControls = @("mfa")
                }
            }

            { $manager.DeployPolicy($validPolicy) } | Should -Not -Throw
        }
    }

    Context "Risk Calculation" {
        It "Should identify high-risk policies" {
            $highRiskPolicy = @{
                Conditions = @{
                    Users = @{
                        IncludeUsers = @("All")
                    }
                    ClientAppTypes = @("Other")
                }
            }

            $risk = $manager.CalculatePolicyRisk($highRiskPolicy)
            $risk | Should -Be "High"
        }
    }
}