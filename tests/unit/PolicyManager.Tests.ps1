Describe "ConditionalAccessPolicyManager" {
    BeforeAll {
        # Load module under test
        $modulePath = Join-Path $PSScriptRoot "../../src/modules/policy-management/policy_manager.ps1"
        Import-Module $modulePath -Force

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

    Context "Access Evaluation" {
        It "Should allow access with default MFA when no policies match" {
            $request = @{
                user = "user@contoso.com"
                application = "App1"
                platform = "windows"
                location = "loc1"
                deviceCompliance = $true
            }

            { $manager.EvaluateAccess($request) } | Should -Not -Throw
            $decision = $manager.EvaluateAccess($request)
            $decision.Granted | Should -Be $true
            $decision.RequiredControls | Should -Contain "mfa"
        }

        It "Should bypass for emergency access" {
            $request = @{ isEmergencyAccess = $true }
            $decision = $manager.EvaluateAccess($request)
            $decision.Granted | Should -Be $true
            $decision.BypassReason | Should -Be "EmergencyAccess"
        }
    }

    Context "Policy Removal" {
        It "Should not throw when removing a policy offline" {
            { $manager.RemovePolicy([guid]::NewGuid().Guid) } | Should -Not -Throw
        }
    }
}