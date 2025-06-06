# Pester tests for PolicyValidator class
# Test suite for src/modules/validation/policy_validator.ps1

BeforeAll {
    Import-Module $PSScriptRoot/../../src/modules/validation/policy_validator.ps1 -Force

    # Global Mocks
    Mock Get-MgIdentityConditionalAccessPolicy {
        Write-Verbose "Mocked Get-MgIdentityConditionalAccessPolicy in PolicyValidator.Tests.ps1"
        return @() # Default to no existing policies
    } -ModuleName *

    # Helper to create mock CA Policy HASHTABLES (as PolicyValidator often deals with definitions)
    $script:NewMockPolicyDefinition = {
        param (
            [string]$DisplayName = "Test Policy Definition",
            [string]$State = "enabled",
            [hashtable]$Users = @{ IncludeUsers = @("All"); ExcludeUsers = @(); IncludeGuestsOrExternalUsers = @() },
            [hashtable]$Applications = @{ IncludeApplications = @("All"); ExcludeApplications = @(); IncludeUserActions = @() },
            [hashtable]$GrantControls = @{ Operator = "OR"; BuiltInControls = @("mfa") },
            [hashtable]$SessionControls = @{ SignInFrequency = @{ Value = 8; Type = "hours" } }, # Default good value
            [array]$ClientAppTypes = @("browser", "mobile"),
            [array]$SignInRiskLevels = @(), # Empty means not configured
            [array]$UserRiskLevels = @()   # Empty means not configured
        )
        return @{
            DisplayName     = $DisplayName
            State           = $State
            Conditions      = @{
                Users            = $Users
                Applications     = $Applications
                ClientAppTypes   = $ClientAppTypes
                SignInRiskLevels = $SignInRiskLevels
                UserRiskLevels   = $UserRiskLevels
                # Platforms, Locations can be added if specific tests need them
            }
            GrantControls   = $GrantControls
            SessionControls = $SessionControls
        }
    }
}

AfterAll {
    Remove-Variable -Name "NewMockPolicyDefinition" -Scope script -ErrorAction SilentlyContinue
}

Describe 'PolicyValidator Class' {
    $validator = $null

    BeforeEach {
        $validator = [PolicyValidator]::new()
        # Reset mocks that might be changed per test
        Mock Get-MgIdentityConditionalAccessPolicy { return @() } -ModuleName *
    }

    Context 'Constructor' {
        It 'Initializes with default validation rules' {
            $validator.ValidationRules.Should().Not().BeNullOrEmpty()
            $validator.ValidationRules.ContainsKey('RequiredProperties').Should().BeTrue()
            $validator.ValidationRules.ContainsKey('SecurityBaseline').Should().BeTrue()
        }
    }

    Context 'ValidatePolicy Method' {
        It 'Flags policy as invalid if missing a required property (e.g., DisplayName)' {
            $policyDef = $script:NewMockPolicyDefinition
            $policyDef.Remove('DisplayName')
            $result = $validator.ValidatePolicy($policyDef)
            $result.IsValid.Should().BeFalse()
            $result.Errors.Should().Contain("Missing required property: DisplayName")
        }

        It 'Warns if policy targets "All" users' {
            $policyDef = $script:NewMockPolicyDefinition -Users @{ IncludeUsers = @("All") } # Default of helper
            $result = $validator.ValidatePolicy($policyDef)
            $result.Warnings.Should().Contain("Policy applies to all users - consider scope restriction")
        }

        It 'Flags policy as invalid if including a restricted application' {
            # Assuming "Microsoft Graph Explorer" is in default ValidationRules.Conditions.RestrictedApplications
            $policyDef = $script:NewMockPolicyDefinition -Applications @{ IncludeApplications = @("Microsoft Graph Explorer") }
            $result = $validator.ValidatePolicy($policyDef)
            $result.IsValid.Should().BeFalse()
            $result.Errors.Should().Contain("Restricted application included: Microsoft Graph Explorer")
        }

        It 'Recommends MFA if not required by policy' {
            $policyDef = $script:NewMockPolicyDefinition -GrantControls @{ Operator = "OR"; BuiltInControls = @() }
            $result = $validator.ValidatePolicy($policyDef)
            $result.Recommendations.Should().Contain("Consider adding MFA requirement")
        }

        It 'Warns if session duration exceeds recommended maximum' {
            # Assuming MaxSessionDuration is 8 (hours) in default rules
            $policyDef = $script:NewMockPolicyDefinition -SessionControls @{ SignInFrequency = @{ Value = 10; Type = "hours" } }
            $result = $validator.ValidatePolicy($policyDef)
            $result.Warnings.Should().Contain("Session duration exceeds recommended maximum")
        }

        It 'Includes conflict warnings if CheckPolicyConflicts returns conflicts' {
            $policyDef = $script:NewMockPolicyDefinition
            Mock ($validator.CheckPolicyConflicts) { return @("Conflict with Policy X", "Conflict with Policy Y") }
            $result = $validator.ValidatePolicy($policyDef)
            $result.Warnings.Should().Contain("Potential policy conflicts detected: Conflict with Policy X; Conflict with Policy Y")
        }

        It 'Returns IsValid = true and minimal messages for a compliant policy' {
            $policyDef = $script:NewMockPolicyDefinition # Helper creates a generally compliant policy
            Mock ($validator.CheckPolicyConflicts) { return @() } # No conflicts
            $result = $validator.ValidatePolicy($policyDef)
            $result.IsValid.Should().BeTrue()
            $result.Errors.Should().BeEmpty()
            # Default policy from helper might still trigger some general warnings/recommendations (e.g. "All users")
            # To make this test more precise, create a very specific "perfect" policy:
            $perfectPolicy = $script:NewMockPolicyDefinition -Users @{ IncludeUsers = @("group-id") } `
                                                            -Applications @{ IncludeApplications = @("app-id") }
            $resultPerfect = $validator.ValidatePolicy($perfectPolicy)
            $resultPerfect.IsValid.Should().BeTrue()
            $resultPerfect.Errors.Should().BeEmpty()
            $resultPerfect.Warnings.Should().BeEmptyOrNull() # Or specific if any still apply
            $resultPerfect.Recommendations.Should().BeEmptyOrNull() # Or specific if any still apply
        }
    }

    Context 'CheckPolicyConflicts Method' {
        $newPolicyDef = $script:NewMockPolicyDefinition -DisplayName "New Policy"

        It 'Returns conflict message if DetectConflict returns true for an existing policy' {
            $existingPolicy1 = [pscustomobject]@{ DisplayName = "Existing Policy 1"; Conditions = @{}; GrantControls = @{} } # Cast to PSCustomObject for existing policies
            Mock Get-MgIdentityConditionalAccessPolicy { return @($existingPolicy1) }
            Mock ($validator.DetectConflict) { param($new, $existing) return ($existing.DisplayName -eq "Existing Policy 1") }

            $conflicts = $validator.CheckPolicyConflicts($newPolicyDef)
            $conflicts.Should().HaveCount(1)
            $conflicts[0].Should().Be("Conflict with policy: Existing Policy 1")
        }

        It 'Returns multiple messages if conflicts with multiple policies' {
            $existingPolicy1 = [pscustomobject]@{ DisplayName = "Existing Policy 1" }
            $existingPolicy2 = [pscustomobject]@{ DisplayName = "Existing Policy 2" }
            Mock Get-MgIdentityConditionalAccessPolicy { return @($existingPolicy1, $existingPolicy2) }
            Mock ($validator.DetectConflict) { return $true } # Mock to always return conflict for simplicity

            $conflicts = $validator.CheckPolicyConflicts($newPolicyDef)
            $conflicts.Should().HaveCount(2)
            $conflicts.Should().BeEquivalentTo(@("Conflict with policy: Existing Policy 1", "Conflict with policy: Existing Policy 2"))
        }

        It 'Returns empty array if no conflicts detected' {
            $existingPolicy1 = [pscustomobject]@{ DisplayName = "Existing Policy 1" }
            Mock Get-MgIdentityConditionalAccessPolicy { return @($existingPolicy1) }
            Mock ($validator.DetectConflict) { return $false } # No conflict

            $conflicts = $validator.CheckPolicyConflicts($newPolicyDef)
            $conflicts.Should().BeEmpty()
        }
    }

    Context 'DetectConflict Method (Hidden)' {
        $newPolicy = @{ conditions = @{}; grantControls = @{} } # Simplified for this context
        $existingPolicy = [pscustomobject]@{ Conditions = @{}; GrantControls = @{} }

        It 'Returns $true if User, App, and Control checks all return $true' {
            Mock ($validator.CheckUserOverlap) { return $true }
            Mock ($validator.CheckApplicationOverlap) { return $true }
            Mock ($validator.CheckControlConflict) { return $true }
            $validator.DetectConflict($newPolicy, $existingPolicy).Should().BeTrue()
        }

        It 'Returns $false if CheckUserOverlap returns $false' {
            Mock ($validator.CheckUserOverlap) { return $false }
            Mock ($validator.CheckApplicationOverlap) { return $true }
            Mock ($validator.CheckControlConflict) { return $true }
            $validator.DetectConflict($newPolicy, $existingPolicy).Should().BeFalse()
        }

        It 'Returns $false if CheckApplicationOverlap returns $false' {
            Mock ($validator.CheckUserOverlap) { return $true }
            Mock ($validator.CheckApplicationOverlap) { return $false }
            Mock ($validator.CheckControlConflict) { return $true }
            $validator.DetectConflict($newPolicy, $existingPolicy).Should().BeFalse()
        }

        It 'Returns $false if CheckControlConflict returns $false' {
            Mock ($validator.CheckUserOverlap) { return $true }
            Mock ($validator.CheckApplicationOverlap) { return $true }
            Mock ($validator.CheckControlConflict) { return $false }
            $validator.DetectConflict($newPolicy, $existingPolicy).Should().BeFalse()
        }
    }

    Context 'CheckUserOverlap Method (Hidden)' {
        # Test cases for CheckUserOverlap
        # Format: @(NewUsers, ExistingUsers, ExpectedResult)
        $userOverlapTestCases = @(
            @{ NU = @{ includeUsers = @("All") }; EU = @{ IncludeUsers = @("All") }; Expected = $true; Desc = "Both All users" }
            @{ NU = @{ includeUsers = @("All") }; EU = @{ IncludeUsers = @("user1") }; Expected = $true; Desc = "New All, Existing specific" }
            @{ NU = @{ includeUsers = @("user1") }; EU = @{ IncludeUsers = @("All") }; Expected = $true; Desc = "New specific, Existing All" }
            @{ NU = @{ includeUsers = @("user1", "user2") }; EU = @{ IncludeUsers = @("user2", "user3") }; Expected = $true; Desc = "Specific with overlap (user2)" }
            @{ NU = @{ includeUsers = @("user1") }; EU = @{ IncludeUsers = @("user2") }; Expected = $false; Desc = "Specific with no overlap" }
            # Current SUT CheckUserOverlap uses Compare-Object on includeUsers arrays directly.
            # It does not deeply inspect ExcludeUsers or IncludeGroups against each other beyond the "All" check.
        )

        foreach ($testCase in $userOverlapTestCases) {
            It "Should return $($testCase.Expected) for $($testCase.Desc)" {
                $validator.CheckUserOverlap($testCase.NU, $testCase.EU).Should().Be($testCase.Expected)
            }
        }
    }

    Context 'CheckApplicationOverlap Method (Hidden)' {
        # Test cases for CheckApplicationOverlap
        # Format: @(NewApplications, ExistingApplications, ExpectedResult, Description)
        $appOverlapTestCases = @(
            @{ NA = @{ includeApplications = @("All") }; EA = @{ IncludeApplications = @("All") }; Expected = $true; Desc = "Both All apps" }
            @{ NA = @{ includeApplications = @("All") }; EA = @{ IncludeApplications = @("app1"); ExcludeApplications = @() }; Expected = $true; Desc = "New All, Existing specific (app1 not excluded)" }
            @{ NA = @{ includeApplications = @("All"); excludeApplications = @("app1") }; EA = @{ IncludeApplications = @("app1") }; Expected = $false; Desc = "New All (excludes app1), Existing app1" }
            @{ NA = @{ includeApplications = @("app1", "app2") }; EA = @{ IncludeApplications = @("app2", "app3") }; Expected = $true; Desc = "Specific with overlap (app2)" }
            @{ NA = @{ includeApplications = @("app1") }; EA = @{ IncludeApplications = @("app2") }; Expected = $false; Desc = "Specific with no overlap" }
            @{ NA = @{ includeApplications = @("All") }; EA = @{ IncludeApplications = @("None"); ExcludeApplications = @() }; Expected = $true; Desc = "New All, Existing 'None' (counts as specific for overlap)" } # 'None' is treated as specific
            @{ NA = @{ includeApplications = @("app1"); includeUserActions = @("all") }; EA = @{ IncludeApplications = @("app1"); includeUserActions = @("register") }; Expected = $true; Desc = "Same app, New all actions, Existing specific action" }
            @{ NA = @{ includeApplications = @("app1"); includeUserActions = @("register") }; EA = @{ IncludeApplications = @("app2"); includeUserActions = @("register") }; Expected = $false; Desc = "Different apps, same specific action" }
        )
        # Note: The SUT's CheckApplicationOverlap has detailed logic for "All", specific includes/excludes, and user actions.
        # These test cases aim to cover some of those paths.

        foreach ($testCase in $appOverlapTestCases) {
            It "Should return $($testCase.Expected) for $($testCase.Desc)" {
                $validator.CheckApplicationOverlap($testCase.NA, $testCase.EA).Should().Be($testCase.Expected)
            }
        }
    }

    Context 'CheckControlConflict Method (Hidden)' {
        # Test cases for CheckControlConflict
        # Format: @(NewGrantControls, ExistingGrantControls, ExpectedResult, Description)
        $controlConflictTestCases = @(
            @{ NGC = @{ builtInControls = @("block") }; EGC = @{ BuiltInControls = @("mfa") }; Expected = $true; Desc = "New blocks, Existing grants MFA" }
            @{ NGC = @{ builtInControls = @("mfa") }; EGC = @{ BuiltInControls = @("block") }; Expected = $true; Desc = "New grants MFA, Existing blocks" }
            @{ NGC = @{ builtInControls = @("block") }; EGC = @{ BuiltInControls = @("block") }; Expected = $false; Desc = "Both block" }
            @{ NGC = @{ builtInControls = @("mfa") }; EGC = @{ BuiltInControls = @("compliantDevice") }; Expected = $false; Desc = "Both grant different controls (cumulative)" }
            @{ NGC = @{}; EGC = @{ BuiltInControls = @("mfa") }; Expected = $false; Desc = "New no controls, Existing grants MFA" }
            @{ NGC = @{ builtInControls = @("mfa") }; EGC = @{}; Expected = $false; Desc = "New grants MFA, Existing no controls" }
            @{ NGC = @{}; EGC = @{}; Expected = $false; Desc = "Both no controls" }
            @{ NGC = @{ builtInControls = @("block") }; EGC = @{}; Expected = $false; Desc = "New blocks, Existing no controls (no positive grant to conflict with)" }
        )
        # The SUT's CheckControlConflict warns for cumulative grant controls but returns $false (no conflict).

        foreach ($testCase in $controlConflictTestCases) {
            It "Should return $($testCase.Expected) for $($testCase.Desc)" {
                if ($testCase.Desc -match "Both grant different controls") { # Expect a warning for this specific case
                    Mock Write-Warning { } # Suppress or verify warning for this test
                }
                $validator.CheckControlConflict($testCase.NGC, $testCase.EGC).Should().Be($testCase.Expected)
            }
        }

        It 'Issues a warning for cumulative grant controls' {
            $ngc = @{ builtInControls = @("mfa") }
            $egc = @{ BuiltInControls = @("compliantDevice") }
            $warningCalled = $false
            Mock Write-Warning -MockWith { $warningCalled = $true }
            $validator.CheckControlConflict($ngc, $egc) # Should be $false
            $warningCalled.Should().BeTrue("Warning should be issued for cumulative grant controls.")
        }
    }
}
