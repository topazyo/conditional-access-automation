# Pester Test File for Invoke-PolicyCleanup.ps1

# BeforeAll block to dot-source the script under test, making its functions available.
BeforeAll {
    # Construct the path to the script relative to this test file's location
    $scriptToTestPath = Join-Path $PSScriptRoot "..\..\scripts\maintenance\Invoke-PolicyCleanup.ps1"

    # Dot-source the script to make its functions available in the test scope
    . $scriptToTestPath

    Write-Host "Dot-sourced Invoke-PolicyCleanup.ps1 for testing."

    # Any other global setup for these tests can go here.
    # For example, if specific mocks are needed for ALL Describe blocks.
}

# Helper function to create a mock PolicyManager instance with a trackable DeployPolicy method.
# This function will be used by tests for Invoke-CaPolicyMerge.
function New-MockPolicyManagerInstance {
    $deployCalls = [System.Collections.Generic.List[object]]::new()
    $mockMgr = [PSCustomObject]@{
        DeployPolicy = {
            param([hashtable]$policyDefinition) # Ensure param matches expected type
            $deployCalls.Add($policyDefinition)
            Write-Verbose "Mocked Instance DeployPolicy called for: $($policyDefinition.displayName)"
        }
        DeployPolicyCalls = $deployCalls # Expose for assertions in tests
        # Add other methods of ConditionalAccessPolicyManager if they need to be mocked by tests
        GetPolicyMap = { Write-Verbose "Mocked GetPolicyMap"; return @{} }
        RemovePolicy = { param([string]$policyId, [switch]$WhatIf) Write-Verbose "Mocked RemovePolicy for $policyId" }
    }
    return $mockMgr
}

# Tests for Merge-CaLocationConditions
Describe "Invoke-PolicyCleanup - Merge-CaLocationConditions Helper" {
    # (PSScriptRoot is available if Pester 5+ runs the file directly)
    # BeforeAll if needed, or rely on the top-level BeforeAll for dot-sourcing

    Context "includeLocations merging" {
        It "Should return 'AllTrusted' if A is 'All' and B is 'AllTrusted'" {
            $locA = @{ includeLocations = @("All"); excludeLocations = @() }
            $locB = @{ includeLocations = @("AllTrusted"); excludeLocations = @() }
            $merged = Merge-CaLocationConditions $locA $locB
            $merged.includeLocations | Should -BeExactly "AllTrusted"
        }

        It "Should return specific GUIDs if A has GUIDs and B is 'All'" {
            $locA = @{ includeLocations = @("guid1", "guid2"); excludeLocations = @() }
            $locB = @{ includeLocations = @("All"); excludeLocations = @() }
            $merged = Merge-CaLocationConditions $locA $locB
            $merged.includeLocations | Should -BeEquivalentTo @("guid1", "guid2")
        }

        It "Should intersect specific GUIDs if both A and B have GUID lists" {
            $locA = @{ includeLocations = @("guid1", "guid2"); excludeLocations = @() }
            $locB = @{ includeLocations = @("guid2", "guid3"); excludeLocations = @() }
            $merged = Merge-CaLocationConditions $locA $locB
            $merged.includeLocations | Should -BeEquivalentTo @("guid2")
        }

        It "Should return an empty array if GUID intersections are empty" {
            $locA = @{ includeLocations = @("guid1"); excludeLocations = @() }
            $locB = @{ includeLocations = @("guid3"); excludeLocations = @() }
            $merged = Merge-CaLocationConditions $locA $locB
            $merged.includeLocations | Should -BeEmpty
        }

        It "Should handle one input object being null" {
            $locA = @{ includeLocations = @("guid1"); excludeLocations = @() }
            $merged = Merge-CaLocationConditions $locA $null
            $merged.includeLocations | Should -BeEquivalentTo @("guid1")
            $merged.excludeLocations | Should -BeEmpty
        }

        It "Should handle includeLocations property being null or absent in one object" {
            $locA = @{ includeLocations = @("guid1"); excludeLocations = @("guid_ex_A") }
            $locB = @{ excludeLocations = @("guid_ex_B") } # includeLocations is implicitly null
            $merged = Merge-CaLocationConditions $locA $locB
            $merged.includeLocations | Should -BeEquivalentTo @("guid1")
        }
    }

    Context "excludeLocations merging" {
        It "Should union excludeLocations lists and remove duplicates" {
            $locA = @{ includeLocations = @("All"); excludeLocations = @("guid_ex_A", "guid_ex_common") }
            $locB = @{ includeLocations = @("All"); excludeLocations = @("guid_ex_B", "guid_ex_common") }
            $merged = Merge-CaLocationConditions $locA $locB
            $merged.excludeLocations | Should -BeEquivalentTo @("guid_ex_A", "guid_ex_common", "guid_ex_B")
        }
    }
}

# Tests for Merge-CaPlatformConditions
Describe "Invoke-PolicyCleanup - Merge-CaPlatformConditions Helper" {
    Context "includePlatforms merging" {
        It "Should return specific types if A has types and B is 'all'" {
            $platA = @{ includePlatforms = @("windows", "iOS"); excludePlatforms = @() }
            $platB = @{ includePlatforms = @("all"); excludePlatforms = @() }
            $merged = Merge-CaPlatformConditions $platA $platB
            $merged.includePlatforms | Should -BeEquivalentTo @("windows", "iOS")
        }

        It "Should intersect specific types if both A and B have type lists" {
            $platA = @{ includePlatforms = @("windows", "iOS"); excludePlatforms = @() }
            $platB = @{ includePlatforms = @("iOS", "macOS"); excludePlatforms = @() }
            $merged = Merge-CaPlatformConditions $platA $platB
            $merged.includePlatforms | Should -BeEquivalentTo @("iOS")
        }
    }
    Context "excludePlatforms merging" {
        It "Should union excludePlatforms lists" {
            $platA = @{ includePlatforms = @("all"); excludePlatforms = @("android") }
            $platB = @{ includePlatforms = @("all"); excludePlatforms = @("linux", "android") }
            $merged = Merge-CaPlatformConditions $platA $platB
            $merged.excludePlatforms | Should -BeEquivalentTo @("android", "linux")
        }
    }
}

# Tests for Merge-CaClientAppTypes
Describe "Invoke-PolicyCleanup - Merge-CaClientAppTypes Helper" {
    It "Should return specific types if A has types and B is 'all'" {
        $typesA = @("browser", "mobileApps")
        $typesB = @("all")
        $merged = Merge-CaClientAppTypes $typesA $typesB
        $merged | Should -BeEquivalentTo @("browser", "mobileApps")
    }

    It "Should intersect specific types if both A and B have type lists" {
        $typesA = @("browser", "mobileApps")
        $typesB = @("mobileApps", "other")
        $merged = Merge-CaClientAppTypes $typesA $typesB
        $merged | Should -BeEquivalentTo @("mobileApps")
    }
     It "Should return empty array if intersection is empty" {
        $typesA = @("browser")
        $typesB = @("other")
        $merged = Merge-CaClientAppTypes $typesA $typesB
        $merged | Should -BeEmpty
    }
    It "Should handle one input being null or empty" {
        $typesA = @("browser")
        $merged = Merge-CaClientAppTypes $typesA $null
        $merged | Should -BeEquivalentTo @("browser")
        $merged2 = Merge-CaClientAppTypes @() $typesA
        $merged2 | Should -BeEquivalentTo @("browser")
    }
}

# Tests for Merge-CaRiskLevelConditions
Describe "Invoke-PolicyCleanup - Merge-CaRiskLevelConditions Helper" {
    It "Should union risk level lists and remove duplicates" {
        $levelsA = @("high", "medium")
        $levelsB = @("medium", "low")
        $merged = Merge-CaRiskLevelConditions $levelsA $levelsB
        $merged | Should -BeEquivalentTo @("high", "medium", "low")
    }
    It "Should handle one list being null or empty" {
        $levelsA = @("high")
        $merged = Merge-CaRiskLevelConditions $levelsA $null
        $merged | Should -BeEquivalentTo @("high")
    }
}

# Tests for Merge-CaSessionControls
Describe "Invoke-PolicyCleanup - Merge-CaSessionControls Helper" {
    Context "signInFrequency merging" {
        It "Should pick shorter duration (10 hours vs 1 day)" {
            $sessionA = @{ signInFrequency = @{ value = 10; type = "hours" } }
            $sessionB = @{ signInFrequency = @{ value = 1; type = "days" } }
            $merged = Merge-CaSessionControls $sessionA $sessionB
            $merged.signInFrequency.value | Should -Be 10
            $merged.signInFrequency.type | Should -Be "hours"
        }
         It "Should pick defined if one is null" {
            $sessionA = $null
            $sessionB = @{ signInFrequency = @{ value = 1; type = "days" } }
            $merged = Merge-CaSessionControls $sessionA $sessionB
            $merged.signInFrequency.value | Should -Be 1
            $merged.signInFrequency.type | Should -Be "days"
        }
    }
    Context "persistentBrowserSession merging" {
        It "Should pick 'isEnabled = $false' if policies differ" {
            $sessionA = @{ persistentBrowserSession = @{ isEnabled = $true } }
            $sessionB = @{ persistentBrowserSession = @{ isEnabled = $false } }
            $merged = Merge-CaSessionControls $sessionA $sessionB
            $merged.persistentBrowserSession.isEnabled | Should -BeFalse
        }
    }
    Context "disableResilienceDefaults merging" {
        It "Should pick '$false' (resilience enabled) if policies differ" {
            $sessionA = @{ disableResilienceDefaults = $true }
            $sessionB = @{ disableResilienceDefaults = $false }
            $merged = Merge-CaSessionControls $sessionA $sessionB
            $merged.disableResilienceDefaults | Should -BeFalse
        }
        It "Should pick '$false' if one is true and other is not defined (implicit false)" {
            $sessionA = @{ disableResilienceDefaults = $true }
            $sessionB = @{ signInFrequency = @{ value = 10; type = "hours" } }
            $merged = Merge-CaSessionControls $sessionA $sessionB
            $merged.disableResilienceDefaults | Should -BeFalse
        }
    }
    Context "cloudAppSecurity merging" {
        It "Should pick 'isEnabled = $true' and stricter type ('blockDownloads') if policies differ" {
            $sessionA = @{ cloudAppSecurity = @{ isEnabled = $false; cloudAppSecuritySessionType = 'monitorOnly' } }
            $sessionB = @{ cloudAppSecurity = @{ isEnabled = $true; cloudAppSecuritySessionType = 'blockDownloads'} }
            $merged = Merge-CaSessionControls $sessionA $sessionB
            $merged.cloudAppSecurity.isEnabled | Should -BeTrue
            $merged.cloudAppSecurity.cloudAppSecuritySessionType | Should -Be 'blockDownloads'
        }
    }
    It "Should return null if both inputs are null" {
        Merge-CaSessionControls $null $null | Should -BeNull
    }
    It "Should deep copy non-null input if one is null" {
        $sessionA = @{ signInFrequency = @{ value = 5; type = "hours" } }
        $copy = Copy-CaObject $sessionA # Assuming Copy-CaObject is available via dot-sourcing
        $merged = Merge-CaSessionControls $copy $null
        $merged.signInFrequency.value | Should -Be 5
        $copy.signInFrequency.value = 10 # Modify original
        $merged.signInFrequency.value | Should -Be 5 # Merged should be independent
    }
}

Describe "Invoke-PolicyCleanup - Invoke-CaPolicyMerge Core Function" {
    # BeforeAll/BeforeEach could be used if common setup for this Describe is extensive.
    # The New-MockPolicyManagerInstance function is already defined at the top of the file.

    # Sample policies for testing Invoke-CaPolicyMerge
    $policyADefinition = @{
        displayName = "Policy A - Base"
        state = "enabled"
        Id = "policyA-id"
        conditions = @{
            users = @{ includeUsers = @("groupA") }
            applications = @{ includeApplications = @("app1") }
            locations = @{ includeLocations = @("AllTrusted"); excludeLocations = @("locX") }
            clientAppTypes = @("browser")
        }
        grantControls = @{ Operator = "OR"; builtInControls = @("mfa") }
        sessionControls = @{ signInFrequency = @{ value = 12; type = "hours"} }
    }

    $policyBDefinition = @{
        displayName = "Policy B - Overlap"
        state = "enabled"
        Id = "policyB-id"
        conditions = @{
            users = @{ includeUsers = @("groupA") }
            applications = @{ includeApplications = @("app1") }
            locations = @{ includeLocations = @("All"); excludeLocations = @("locY") }
            clientAppTypes = @("browser", "mobileApps")
            signInRiskLevels = @("high")
        }
        grantControls = @{ Operator = "OR"; builtInControls = @("mfa") }
        sessionControls = @{ signInFrequency = @{ value = 1; type = "days"} }
    }

    Context "-WhatIf scenarios for Invoke-CaPolicyMerge" {
        It "Should output proposed actions and NOT call DeployPolicy when -WhatIf is used" {
            $mockMgr = New-MockPolicyManagerInstance

            # Invoke with -WhatIf (implicitly via $WhatIfPreference = $true or explicitly)
            Invoke-CaPolicyMerge -PolicyA $policyADefinition -PolicyB $policyBDefinition -PolicyManager $mockMgr -WhatIf | Out-Null

            $mockMgr.DeployPolicyCalls.Count | Should -Be 0
            # In a real test, capture Write-Host/Write-Verbose and verify the "WhatIf" messages.
        }
    }

    Context "Actual Merge Operations for Invoke-CaPolicyMerge (simulating -Force or $PSCmdlet.ShouldProcess returning true)" {
        BeforeEach {
            # This mock makes ShouldProcess always return true for this context
            Mock -CommandName ShouldProcess -ModuleName $TestDrive -MockWith { return $true } -Verifiable # $TestDrive is Pester's scope for its own cmdlets
        }
        AfterEach {
            Remove-Mock -CommandName ShouldProcess -ModuleName $TestDrive -Verifiable
        }

        It "Should create a new merged policy and disable original policies" {
            $mockMgr = New-MockPolicyManagerInstance
            Invoke-CaPolicyMerge -PolicyA $policyADefinition -PolicyB $policyBDefinition -PolicyManager $mockMgr

            $mockMgr.DeployPolicyCalls.Count | Should -Be 3

            $mergedDeployedPolicy = $mockMgr.DeployPolicyCalls[0]
            $mergedDeployedPolicy.displayName | Should -Be "Merged: Policy A - Base and Policy B - Overlap"
            $mergedDeployedPolicy.conditions.locations.includeLocations | Should -BeExactly "AllTrusted"
            $mergedDeployedPolicy.conditions.locations.excludeLocations | Should -BeEquivalentTo @("locX", "locY")
            $mergedDeployedPolicy.conditions.clientAppTypes | Should -BeEquivalentTo @("browser")
            $mergedDeployedPolicy.conditions.signInRiskLevels | Should -BeEquivalentTo @("high")
            $mergedDeployedPolicy.sessionControls.signInFrequency.value | Should -Be 12

            $disabledPolicyA = $mockMgr.DeployPolicyCalls[1]
            $disabledPolicyA.displayName | Should -Be $policyADefinition.displayName
            $disabledPolicyA.state | Should -Be "disabled"

            $disabledPolicyB = $mockMgr.DeployPolicyCalls[2]
            $disabledPolicyB.displayName | Should -Be $policyBDefinition.displayName
            $disabledPolicyB.state | Should -Be "disabled"
        }

        It "Should generate a correct merged policy name, truncating if necessary" {
            $mockMgr = New-MockPolicyManagerInstance
            $longNamePolicyA = Copy-CaObject $policyADefinition # Assuming Copy-CaObject is available
            $longNamePolicyA.displayName = ("A" * 150)
            $longNamePolicyB = Copy-CaObject $policyBDefinition
            $longNamePolicyB.displayName = ("B" * 150)

            Invoke-CaPolicyMerge -PolicyA $longNamePolicyA -PolicyB $longNamePolicyB -PolicyManager $mockMgr

            $mergedName = $mockMgr.DeployPolicyCalls[0].displayName
            $expectedTruncatedName = "Merged: $($longNamePolicyA.displayName) and $($longNamePolicyB.displayName)".Substring(0, 250)
            $mergedName | Should -BeExactly $expectedTruncatedName
        }

        It "Should remove empty 'locations' section from merged policy if it becomes empty" {
            $mockMgr = New-MockPolicyManagerInstance
            $policyC = @{
                displayName = "Policy C - Disjoint Locations"; Id="idC"; state="enabled"
                conditions = @{ users = @{ includeUsers = @("groupA") }; applications = @{ includeApplications = @("app1") }; locations = @{ includeLocations = @("loc_C1") } }
                grantControls = @{ Operator = "OR"; builtInControls = @("mfa") }
            }
            $policyD = @{
                displayName = "Policy D - Disjoint Locations"; Id="idD"; state="enabled"
                conditions = @{ users = @{ includeUsers = @("groupA") }; applications = @{ includeApplications = @("app1") }; locations = @{ includeLocations = @("loc_D1") } }
                grantControls = @{ Operator = "OR"; builtInControls = @("mfa") }
            }
            Invoke-CaPolicyMerge -PolicyA $policyC -PolicyB $policyD -PolicyManager $mockMgr

            $mergedDeployedPolicy = $mockMgr.DeployPolicyCalls[0]
            ($mergedDeployedPolicy.conditions.PSObject.Properties.Name -contains 'locations') | Should -BeFalse
        }

        It "Should NOT disable original policies if new policy deployment fails" {
            $tempPolicyA = Copy-CaObject $policyADefinition
            $tempPolicyB = Copy-CaObject $policyBDefinition

            $deployCallCount = 0
            $failingMockMgr = [PSCustomObject]@{
                DeployPolicy = {
                    param([hashtable]$policyDef)
                    $deployCallCount++
                    if ($policyDef.displayName -match "Merged:") { throw "Simulated deployment failure for new policy" }
                }
                DeployPolicyCalls = @() # Not used for assertion here, just to fit the helper
            }

            Invoke-CaPolicyMerge -PolicyA $tempPolicyA -PolicyB $tempPolicyB -PolicyManager $failingMockMgr | Should -Throw "Simulated deployment failure for new policy"
            $deployCallCount | Should -Be 1
        }
    }
}
