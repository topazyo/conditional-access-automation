param (
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    [Parameter(Mandatory = $true)]
    [string]$TestEnvironment # Not directly used in this version but good for context
)

BeforeAll {
    # Import required modules
    Import-Module $PSScriptRoot/../../src/modules/policy-management/PolicyManager.ps1 -Force
    # Compliance and RiskAssessor modules are not directly used by PolicyManager integration tests here.
    # Import-Module $PSScriptRoot/../../src/modules/compliance/compliance_manager.ps1 -Force
    # Import-Module $PSScriptRoot/../../src/modules/risk/risk_assessor.ps1 -Force

    # Initialize test context
    $script:testContext = @{
        TenantId = $TenantId
        Environment = $TestEnvironment
        PolicyManager = $null
        TestPolicyIds = [System.Collections.Generic.List[string]]::new() # Store IDs for cleanup
    }

    # Test policy definitions (using hashtables as input for DeployPolicy)
    # Ensure DisplayNames are unique for these tests to avoid conflicts with other policies
    # or previous failed test runs if cleanup didn't complete.
    $baseName = "PSTRE_INT_TEST_" + (Get-Date -Format "yyyyMMddHHmmss")

    $script:testPolicies = @{
        basic = @{
            displayName = "${baseName}_Basic_Policy"
            state = "enabled" # or "disabled" or "enabledForReportingButNotEnforced"
            conditions = @{
                users = @{
                    includeUsers = @("All") # Using "All" for simplicity in test environment setup
                                          # In real tests, use specific test user IDs that exist
                }
                applications = @{
                    includeApplications = @("All")
                }
            }
            grantControls = @{
                operator = "OR" # Changed from AND for basic policy to be less restrictive
                builtInControls = @("mfa")
            }
        }
        complex = @{ # This policy is now used for the update test
            displayName = "${baseName}_Complex_Update_Policy"
            state = "enabled"
            conditions = @{
                users = @{
                    includeUsers = @("All")
                }
                applications = @{
                    includeApplications = @("Office365") # Example, could be specific App ID
                }
                clientAppTypes = @("all") # Ensure this is valid; e.g., "browser", "mobileApps"
                 locations = @{
                    includeLocations = @("AllTrusted") # Requires trusted locations to be configured
                    excludeLocations = @()
                }
            }
            grantControls = @{
                operator = "OR"
                builtInControls = @("mfa", "compliantDevice") # compliantDevice requires Intune
            }
        }
    }

    # Ensure PolicyManager is instantiated after $TenantId is available
    $script:testContext.PolicyManager = [ConditionalAccessPolicyManager]::new($script:testContext.TenantId)
    # The PolicyManager constructor calls Connect-MgGraph. Ensure this is handled if tests run non-interactively.
    # For integration tests, it's assumed the environment/user context is already authenticated.
}

Describe "Conditional Access Policy Integration Tests" {

    Context "Policy Deployment Workflow" {
        It "Should successfully deploy a basic policy" {
            $policyDef = $script:testPolicies.basic
            Write-Host "Deploying basic policy: $($policyDef.displayName)"
            $script:testContext.PolicyManager.DeployPolicy($policyDef) # DeployPolicy is void

            Start-Sleep -Seconds 10 # Allow time for Azure AD replication

            $retrievedPolicies = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$($policyDef.displayName)'" -ErrorAction SilentlyContinue
            $retrievedPolicies.Should().Not().BeNullOrEmpty("Policy '$($policyDef.displayName)' should be found after deployment.")
            # If Get-MgIdentityConditionalAccessPolicy returns a single object directly when one match, or $null when no match,
            # and an array only for multiple matches, the Count check needs to be robust.
            # Let's assume it always returns a collection or $null for safety in tests.
            if ($null -ne $retrievedPolicies -and $retrievedPolicies.GetType().IsArray) {
                ($retrievedPolicies.Count).Should().Be(1, "Expected only one policy with name '$($policyDef.displayName)'")
                $retrievedPolicy = $retrievedPolicies[0]
            } elseif ($null -ne $retrievedPolicies) { # Single object returned
                 $retrievedPolicy = $retrievedPolicies
            } else { # Null returned
                $retrievedPolicy = $null
            }
            $retrievedPolicy.Should().Not().BeNull() # Should have found one

            $retrievedPolicy.DisplayName.Should().Be($policyDef.displayName)
            $retrievedPolicy.State.Should().Be($policyDef.state)
            $retrievedPolicy.GrantControls.Operator.ToLower().Should().Be($policyDef.grantControls.operator.ToLower())

            $script:testContext.TestPolicyIds.Add($retrievedPolicy.Id)
        }

        It "Should update an existing policy's properties" {
            $policyDefToUpdate = $script:testPolicies.complex # Use the 'complex' definition for this test
            $originalDisplayName = $policyDefToUpdate.displayName
            
            Write-Host "Deploying initial version of policy for update test: $originalDisplayName"
            $script:testContext.PolicyManager.DeployPolicy($policyDefToUpdate)
            Start-Sleep -Seconds 10

            $initialPoliciesResult = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$originalDisplayName'"
            $initialPoliciesResult.Should().Not().BeNullOrEmpty("Policy '$originalDisplayName' should exist after initial deployment.")
            $initialPolicy = if ($initialPoliciesResult.GetType().IsArray) { $initialPoliciesResult[0] } else { $initialPoliciesResult }
            ($initialPolicy -ne $null).Should().BeTrue()

            $initialPolicyId = $initialPolicy.Id
            $script:testContext.TestPolicyIds.Add($initialPolicyId) # Add for cleanup
            $initialPolicy.State.Should().Be("enabled")

            # Modify the definition for update
            $updatedPolicyDef = $policyDefToUpdate.PSObject.Copy() # Deep copy for modification
            $updatedPolicyDef.state = 'disabled'
            $updatedPolicyDef.grantControls = @{ operator = "AND"; builtInControls = @("mfa") }


            Write-Host "Updating policy: $originalDisplayName to state '$($updatedPolicyDef.state)'"
            $script:testContext.PolicyManager.DeployPolicy($updatedPolicyDef) # Deploy again with modified definition
            Start-Sleep -Seconds 10

            $retrievedUpdatedPoliciesResult = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$originalDisplayName'"
            $retrievedUpdatedPoliciesResult.Should().Not().BeNullOrEmpty("Policy '$originalDisplayName' should still exist after update.")
            $retrievedUpdatedPolicy = if ($retrievedUpdatedPoliciesResult.GetType().IsArray) { $retrievedUpdatedPoliciesResult[0] } else { $retrievedUpdatedPoliciesResult }
            ($retrievedUpdatedPolicy -ne $null).Should().BeTrue()

            $retrievedUpdatedPolicy.Id.Should().Be($initialPolicyId, "Policy ID should remain the same after update.")
            $retrievedUpdatedPolicy.State.Should().Be('disabled')
            $retrievedUpdatedPolicy.GrantControls.Operator.ToLower().Should().Be("and")
            $retrievedUpdatedPolicy.GrantControls.BuiltInControls.Should().BeEquivalentTo(@("mfa"))
        }
    }

    AfterAll {
        Write-Host "Cleaning up test policies..."
        if ($script:testContext.TestPolicyIds.Count -gt 0) {
            # Make a unique list of IDs to prevent trying to delete the same ID multiple times if it got added more than once
            $uniquePolicyIds = $script:testContext.TestPolicyIds | Select-Object -Unique
            foreach ($policyId in $uniquePolicyIds) {
                Write-Host "Attempting to remove policy with ID: $policyId"
                Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policyId -ErrorAction SilentlyContinue
                # Adding a small delay after each deletion attempt can sometimes help with Graph API consistency.
                Start-Sleep -Seconds 2
            }
            Write-Host "$($uniquePolicyIds.Count) unique test policies scheduled for removal."
        } else {
            Write-Host "No test policies were recorded for cleanup."
        }
    }
}
