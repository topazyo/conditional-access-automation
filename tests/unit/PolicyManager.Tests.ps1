# Pester tests for ConditionalAccessPolicyManager class
# Test suite for src/modules/policy-management/policy_manager.ps1

BeforeAll {
    Import-Module $PSScriptRoot/../../src/modules/policy-management/policy_manager.ps1 -Force

    # Global Mocks
    Mock Connect-MgGraph { Write-Verbose "Mocked Connect-MgGraph"; return $true } -ModuleName *

    # Default mock, can be overridden in specific tests
    Mock Get-MgIdentityConditionalAccessPolicy { Write-Verbose "Mocked Get-MgIdentityConditionalAccessPolicy (Global Default)"; return @() } -ModuleName *

    Mock New-MgIdentityConditionalAccessPolicy {
        param($BodyParameter)
        Write-Verbose "Mocked New-MgIdentityConditionalAccessPolicy called with DisplayName: $($BodyParameter.DisplayName)"
        # Return a mock object that includes an ID, similar to the actual cmdlet
        return [pscustomobject]@{ Id = (New-Guid).Guid; DisplayName = $BodyParameter.DisplayName }
    } -ModuleName *

    Mock Update-MgIdentityConditionalAccessPolicy {
        param($ConditionalAccessPolicyId, $BodyParameter)
        Write-Verbose "Mocked Update-MgIdentityConditionalAccessPolicy called for ID: $ConditionalAccessPolicyId with DisplayName: $($BodyParameter.DisplayName)"
        # Return a mock object
        return [pscustomobject]@{ Id = $ConditionalAccessPolicyId; DisplayName = $BodyParameter.DisplayName }
    } -ModuleName *

    # Helper to create mock CA Policy OBJECTS (like those from Get-MgIdentityConditionalAccessPolicy)
    $script:NewMockCaPolicyObject = {
        param (
            [string]$Id = (New-Guid).Guid,
            [string]$DisplayName = "Mock CA Policy Object",
            [string]$State = "enabled",
            [hashtable]$Users = @{ IncludeUsers = @("All"); ExcludeUsers = @(); IncludeGuestsOrExternalUsers = @() },
            [hashtable]$Applications = @{ IncludeApplications = @("All"); ExcludeApplications = @(); IncludeUserActions = @() },
            [hashtable]$GrantControls = @{ Operator = "OR"; BuiltInControls = @("mfa") },
            [hashtable]$SessionControls = $null, # e.g., @{ SignInFrequency = @{ Value = 24; Type = "hours"}}
            [array]$ClientAppTypes = @("browser", "mobile"),
            [array]$SignInRiskLevels = @(),
            [array]$UserRiskLevels = @()
        )
        return [pscustomobject]@{
            Id              = $Id
            DisplayName     = $DisplayName
            State           = $State
            CreatedDateTime = (Get-Date).AddDays(-5)
            ModifiedDateTime= (Get-Date).AddDays(-2)
            Conditions      = [pscustomobject]@{
                Users            = [pscustomobject]$Users
                Applications     = [pscustomobject]$Applications
                ClientAppTypes   = $ClientAppTypes
                SignInRiskLevels = $SignInRiskLevels
                UserRiskLevels   = $UserRiskLevels
            }
            GrantControls   = [pscustomobject]$GrantControls
            SessionControls = if ($null -ne $SessionControls) { [pscustomobject]$SessionControls } else { $null }
        }
    }

    # Helper for policy definitions (hashtables for DeployPolicy input)
    $script:NewCaPolicyDefinition = {
        param(
            [string]$DisplayName = "Test Policy Definition",
            [string]$State = "enabled",
            [hashtable]$Users = @{ IncludeUsers = @("All") },
            [hashtable]$Applications = @{ IncludeApplications = @("All") },
            [hashtable]$GrantControls = @{ Operator = "OR"; BuiltInControls = @("mfa") },
            [hashtable]$SessionControls = $null
        )
        return @{
            DisplayName     = $DisplayName
            State           = $State
            Conditions      = @{
                Users        = $Users
                Applications = $Applications
            }
            GrantControls   = $GrantControls
            SessionControls = $SessionControls
        }
    }
}

AfterAll {
    Remove-Variable -Name "NewMockCaPolicyObject" -Scope script -ErrorAction SilentlyContinue
    Remove-Variable -Name "NewCaPolicyDefinition" -Scope script -ErrorAction SilentlyContinue
}

Describe 'ConditionalAccessPolicyManager Class' {
    $policyManager = $null
    $mockTenantId = "mock-tenant-id"

    BeforeEach {
        $policyManager = [ConditionalAccessPolicyManager]::new($mockTenantId)
        # Reset mocks that count calls or store parameters
        Clear-MockCallCount -CommandName New-MgIdentityConditionalAccessPolicy, Update-MgIdentityConditionalAccessPolicy, Write-Warning, Get-MgIdentityConditionalAccessPolicy
    }

    Context 'DeployPolicy Method' {
        It 'Creates a NEW policy if no existing policy with the same DisplayName is found' {
            Mock Get-MgIdentityConditionalAccessPolicy { return @() } # No existing policies
            $newPolicyDef = $script:NewCaPolicyDefinition -DisplayName "Brand New Policy"

            $policyManager.DeployPolicy($newPolicyDef)

            Assert-MockCalled -CommandName New-MgIdentityConditionalAccessPolicy -Times 1
            Get-MockCallCount -CommandName New-MgIdentityConditionalAccessPolicy | % {
                $_.Parameters.BodyParameter.DisplayName.Should().Be("Brand New Policy")
            }
            Assert-MockCalled -CommandName Update-MgIdentityConditionalAccessPolicy -Times 0
        }

        It 'UPDATES an existing policy if one with the same DisplayName is found' {
            $existingPolicyId = "existing-policy-123"
            $existingPolicy = $script:NewMockCaPolicyObject -Id $existingPolicyId -DisplayName "My Existing Policy"
            Mock Get-MgIdentityConditionalAccessPolicy { return @($existingPolicy) }

            $updatedPolicyDef = $script:NewCaPolicyDefinition -DisplayName "My Existing Policy" -State "disabled" # Change state for update

            $policyManager.DeployPolicy($updatedPolicyDef)

            Assert-MockCalled -CommandName Update-MgIdentityConditionalAccessPolicy -Times 1
            Get-MockCallCount -CommandName Update-MgIdentityConditionalAccessPolicy | % {
                $_.Parameters.ConditionalAccessPolicyId.Should().Be($existingPolicyId)
                $_.Parameters.BodyParameter.DisplayName.Should().Be("My Existing Policy")
                $_.Parameters.BodyParameter.State.Should().Be("disabled")
            }
            Assert-MockCalled -CommandName New-MgIdentityConditionalAccessPolicy -Times 0
        }

        It 'Issues a WARNING and does NOT create or update if MULTIPLE existing policies have the same DisplayName' {
            $policyName = "Duplicate Name Policy"
            $existingPolicy1 = $script:NewMockCaPolicyObject -Id "dup-id-1" -DisplayName $policyName
            $existingPolicy2 = $script:NewMockCaPolicyObject -Id "dup-id-2" -DisplayName $policyName
            Mock Get-MgIdentityConditionalAccessPolicy { return @($existingPolicy1, $existingPolicy2) }
            # Mock Write-Warning to count its calls for this specific test
            $writeWarningCalls = 0
            Mock Write-Warning -MockWith { $writeWarningCalls++ } -ModuleName *


            $policyDef = $script:NewCaPolicyDefinition -DisplayName $policyName

            $policyManager.DeployPolicy($policyDef)

            # Check if Write-Warning was called at least for the "Multiple existing policies found" message
            # The exact number of calls might depend on other verbose/warning messages not specific to this test condition
            $writeWarningCalls.Should().BeGreaterOrEqual(1)
            # More specific check if possible:
            # Get-MockCallCount -CommandName Write-Warning | Where-Object {$_.Parameters.Message -match "Multiple existing policies found"} | Should -HaveCount 1

            Assert-MockCalled -CommandName New-MgIdentityConditionalAccessPolicy -Times 0
            Assert-MockCalled -CommandName Update-MgIdentityConditionalAccessPolicy -Times 0
        }

        It 'Still validates policy definition before attempting create/update (throws on invalid)' {
            $invalidPolicyDef = $script:NewCaPolicyDefinition -DisplayName "Invalid Def"
            $invalidPolicyDef.Remove("State") # Make it invalid

            # Test for creation scenario
            Mock Get-MgIdentityConditionalAccessPolicy { return @() }
            { $policyManager.DeployPolicy($invalidPolicyDef) }.Should().Throw("Policy definition missing required property: State")
            Assert-MockCalled New-MgIdentityConditionalAccessPolicy -Times 0

            # Test for update scenario
            $existingPolicy = $script:NewMockCaPolicyObject -Id "id1" -DisplayName "Invalid Def"
            Mock Get-MgIdentityConditionalAccessPolicy { return @($existingPolicy) }
             { $policyManager.DeployPolicy($invalidPolicyDef) }.Should().Throw("Policy definition missing required property: State")
            Assert-MockCalled Update-MgIdentityConditionalAccessPolicy -Times 0
        }
    }

    Context 'CalculatePolicyRisk Method (tested via GetPolicyMap)' {
        # Enhanced logic from previous SUT update:
        # Users 'All' (implies guests): +4. Users 'All' (guests excluded/unclear): +3. Many groups: +2. Few: +1.
        # Apps 'All': +3. Many apps: +2. Few: +1.
        # Legacy Auth ('other'): +2.
        # MFA: -2. CompliantDevice: -1. Block: -1.
        # SessionControls SignInFrequency >24h or null: +1. Persistent Browser enabled: +1
        # Risk Levels: High (>=5), Medium (>=2), Low (<2).

        It 'Calculates "High" risk for "All users (guests)" and "All apps"' {
            $policy = $script:NewMockCaPolicyObject -DisplayName 'Test Policy High' `
                                                 -Users @{ IncludeUsers = @('All'); IncludeGuestsOrExternalUsers = @('all') } `
                                                 -Applications @{ IncludeApplications = @('All') } `
                                                 -GrantControls $null `
                                                 -SessionControls $null # SIF null (+1)
            Mock Get-MgIdentityConditionalAccessPolicy { return @($policy) }
            $map = $policyManager.GetPolicyMap()
            # Expected score: Users All+Guests (+4) + Apps All (+3) + SIF Null (+1) = 8. Risk = High.
            $map.($policy.Id).RiskLevel.Should().Be('High')
        }

        It 'Calculates "Medium" risk for "All users (no explicit guests)", specific apps, MFA' {
            $policy = $script:NewMockCaPolicyObject -DisplayName 'Test Policy Medium' `
                                                 -Users @{ IncludeUsers = @('All'); IncludeGuestsOrExternalUsers = @() } `
                                                 -Applications @{ IncludeApplications = @('app1', 'app2') } `
                                                 -GrantControls @{ Operator = 'OR'; BuiltInControls = @('mfa') } `
                                                 -SessionControls @{ SignInFrequency = @{ Value = 8; Type = "hours"}; PersistentBrowser = @{ IsEnabled = $false } } # Good SIF, No PB
            Mock Get-MgIdentityConditionalAccessPolicy { return @($policy) }
            $map = $policyManager.GetPolicyMap()
            # Expected score: Users All (+3) + Apps Few (+1) + MFA (-2) = 2. Risk = Medium.
            $map.($policy.Id).RiskLevel.Should().Be('Medium')
        }

        It 'Calculates "Low" risk for specific users, specific apps, MFA, Compliant Device, good session' {
             $policy = $script:NewMockCaPolicyObject -DisplayName 'Test Policy Low' `
                                                 -Users @{ IncludeUsers = @('group1') } `
                                                 -Applications @{ IncludeApplications = @('app1') } `
                                                 -GrantControls @{ Operator = 'AND'; BuiltInControls = @('mfa', 'compliantDevice') } `
                                                 -SessionControls @{ SignInFrequency = @{ Value = 8; Type = "hours"}; PersistentBrowser = @{ IsEnabled = $false } }
            Mock Get-MgIdentityConditionalAccessPolicy { return @($policy) }
            $map = $policyManager.GetPolicyMap()
            # Expected score: Users Few (+1) + Apps Few (+1) + MFA (-2) + CompliantDevice (-1) = -1. Risk = Low.
            $map.($policy.Id).RiskLevel.Should().Be('Low')
        }

        It 'Calculates "High" risk for Legacy Auth enabled' {
            $policy = $script:NewMockCaPolicyObject -DisplayName 'Test Policy Legacy' `
                                                 -Users @{ IncludeUsers = @('group1') } `
                                                 -Applications @{ IncludeApplications = @('app1') } `
                                                 -ClientAppTypes @('browser', 'mobile', 'other') `
                                                 -GrantControls $null `
                                                 -SessionControls $null # SIF null (+1)
            Mock Get-MgIdentityConditionalAccessPolicy { return @($policy) }
            $map = $policyManager.GetPolicyMap()
            # Expected: Users Few (+1) + Apps Few (+1) + Legacy Auth (+2) + SIF Null (+1) = 5. Risk = High.
            $map.($policy.Id).RiskLevel.Should().Be('High')
        }

        It 'Calculates "High" risk for multiple risk-adding session controls' {
             $policy = $script:NewMockCaPolicyObject -DisplayName 'Test Policy Session Risk' `
                                                 -Users @{ IncludeUsers = @('All'); IncludeGuestsOrExternalUsers = @() } ` # Users All (+3)
                                                 -Applications @{ IncludeApplications = @('app1') } ` # Apps Few (+1)
                                                 -GrantControls $null ` # No reducers
                                                 -SessionControls @{ SignInFrequency = $null; PersistentBrowser = @{ IsEnabled = $true } } # SIF Null (+1), PB True (+1)
            Mock Get-MgIdentityConditionalAccessPolicy { return @($policy) }
            $map = $policyManager.GetPolicyMap()
            # Expected: Users All (+3) + Apps Few (+1) + SIF Null (+1) + Persistent Browser (+1) = 6. Risk = High.
            $map.($policy.Id).RiskLevel.Should().Be('High')
        }
    }
}
