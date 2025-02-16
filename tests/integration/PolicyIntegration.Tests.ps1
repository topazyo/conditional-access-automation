param (
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    [Parameter(Mandatory = $true)]
    [string]$TestEnvironment
)

BeforeAll {
    # Import required modules
    Import-Module "../../src/modules/policy-management/policy_manager.ps1"
    Import-Module "../../src/modules/compliance/compliance_manager.ps1"
    Import-Module "../../src/modules/risk/risk_assessor.ps1"

    # Initialize test context
    $script:testContext = @{
        TenantId = $TenantId
        Environment = $TestEnvironment
        PolicyManager = $null
        TestPolicies = @()
    }

    # Test policy definitions
    $script:testPolicies = @{
        basic = @{
            displayName = "INT_TEST_Basic_Policy"
            state = "enabled"
            conditions = @{
                users = @{
                    includeUsers = @("test-user@domain.com")
                }
                applications = @{
                    includeApplications = @("All")
                }
            }
            grantControls = @{
                operator = "AND"
                builtInControls = @("mfa")
            }
        }
        complex = @{
            displayName = "INT_TEST_Complex_Policy"
            state = "enabled"
            conditions = @{
                users = @{
                    includeGroups = @("test-group-id")
                }
                applications = @{
                    includeApplications = @("Office365")
                }
                platforms = @{
                    includePlatforms = @("android", "iOS")
                }
                locations = @{
                    includeLocations = @("test-location-id")
                }
            }
            grantControls = @{
                operator = "OR"
                builtInControls = @("mfa", "compliantDevice")
            }
        }
    }
}

Describe "Conditional Access Policy Integration Tests" {
    BeforeAll {
        $script:testContext.PolicyManager = [ConditionalAccessPolicyManager]::new($TenantId)
    }

    Context "Policy Deployment Workflow" {
        It "Should successfully deploy a basic policy" {
            # Deploy test policy
            $deployedPolicy = $script:testContext.PolicyManager.DeployPolicy($script:testPolicies.basic)
            $script:testContext.TestPolicies += $deployedPolicy.Id

            # Verify deployment
            $policy = Get-MgIdentityConditionalAccessPolicy -PolicyId $deployedPolicy.Id
            $policy.DisplayName | Should -Be $script:testPolicies.basic.displayName
            $policy.State | Should -Be "enabled"
        }

        It "Should handle complex policy configurations" {
            $deployedPolicy = $script:testContext.PolicyManager.DeployPolicy($script:testPolicies.complex)
            $script:testContext.TestPolicies += $deployedPolicy.Id

            $policy = Get-MgIdentityConditionalAccessPolicy -PolicyId $deployedPolicy.Id
            $policy.Conditions.Platforms.IncludePlatforms | Should -Contain "android"
            $policy.GrantControls.BuiltInControls | Should -Contain "compliantDevice"
        }

        It "Should detect policy conflicts" {
            $conflictingPolicy = $script:testPolicies.basic.Clone()
            $conflictingPolicy.displayName = "INT_TEST_Conflicting_Policy"
            
            # Attempt to deploy conflicting policy
            { $script:testContext.PolicyManager.DeployPolicy($conflictingPolicy) } | 
                Should -Throw -ErrorId "PolicyConflict"
        }
    }

    Context "Policy Evaluation" {
        It "Should correctly evaluate access decisions" {
            $testCase = @{
                user = "test-user@domain.com"
                application = "Office365"
                platform = "android"
                location = "test-location-id"
                deviceCompliance = $true
            }

            $decision = $script:testContext.PolicyManager.EvaluateAccess($testCase)
            $decision.Granted | Should -Be $true
            $decision.RequiredControls | Should -Contain "mfa"
        }
    }

    Context "Emergency Access Scenarios" {
        It "Should handle emergency access overrides" {
            $emergencyCase = @{
                user = "emergency-admin@domain.com"
                isEmergencyAccess = $true
            }

            $decision = $script:testContext.PolicyManager.EvaluateAccess($emergencyCase)
            $decision.Granted | Should -Be $true
            $decision.BypassReason | Should -Be "EmergencyAccess"
        }
    }

    AfterAll {
        # Cleanup test policies
        foreach ($policyId in $script:testContext.TestPolicies) {
            $script:testContext.PolicyManager.RemovePolicy($policyId)
        }
    }
}