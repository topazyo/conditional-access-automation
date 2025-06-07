# Pester tests for AdvancedPolicyAnalyzer class
# Test suite for src/modules/analytics/advanced_analyzer.ps1

BeforeAll {
    Import-Module $PSScriptRoot/../../src/modules/analytics/advanced_analyzer.ps1 -Force

    $script:NewMockCaPolicy = {
        param(
            [string]$Id = (New-Guid).Guid,
            [string]$DisplayName = "Mock Policy $($Id.Substring(0,4))",
            [string]$State = "enabled", # 'enabled', 'disabled', 'enabledForReportingButNotEnforced'
            [hashtable]$Users = @{ IncludeUsers = @("All"); ExcludeUsers = @(); IncludeGroups = @(); ExcludeGroups = @(); IncludeGuestsOrExternalUsers = @() },
            [hashtable]$Applications = @{ IncludeApplications = @("All"); ExcludeApplications = @(); IncludeUserActions = @() },
            [hashtable]$GrantControls = @{ Operator = "OR"; BuiltInControls = @("mfa") }
        )
        return [pscustomobject]@{
            Id              = $Id
            DisplayName     = $DisplayName
            State           = $State
            Conditions      = [pscustomobject]@{
                Users        = [pscustomobject]$Users
                Applications = [pscustomobject]$Applications
                # Locations, Platforms, ClientAppTypes, SignInRiskLevels, UserRiskLevels can be added if needed
            }
            GrantControls   = [pscustomobject]$GrantControls
            SessionControls = $null
        }
    }

    $script:DefaultMockPolicies = @(
        $script:NewMockCaPolicy -Id "P1-Default" -DisplayName "Default Policy 1"
    )
    $script:DefaultSignInLogs = @()
    $script:DefaultAuditLogs = @()
    $script:DefaultUserGroupMap = @{ "user1@example.com" = @("group1-id", "group2-id") }

    # Mock cmdlets that might be called by future implementations or during verbose logging
    Mock Write-Warning { param($Message) $script:CapturedWarnings += $Message } -ModuleName *
    Mock Write-Verbose { param($Message) $script:CapturedVerboseMessages += $Message } -ModuleName *
}

AfterAll {
    Remove-Variable -Name "NewMockCaPolicy" -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name "Default*" -Scope Script -ErrorAction SilentlyContinue
}

Describe 'AdvancedPolicyAnalyzer Class' {
    $analyzer = $null

    BeforeEach {
        $script:CapturedWarnings = [System.Collections.Generic.List[string]]::new()
        $script:CapturedVerboseMessages = [System.Collections.Generic.List[string]]::new()
    }

    Context 'Constructor' {
        It 'Initializes with valid empty inputs (policies array can be empty but not null for some checks)' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@(), $script:DefaultSignInLogs, $script:DefaultAuditLogs, $null)
            $analyzer.Should().Not().BeNull()
            $analyzer.AllPolicies.Should().BeEmpty() # Handled by constructor logic
            # Warning for empty policies is expected based on SUT
            $script:CapturedWarnings.Should().ContainMatch("AdvancedPolicyAnalyzer initialized with no policies.")
        }

        It 'Initializes with valid policy, signin, audit, and userGroupMap inputs and sets properties' {
            $analyzer = [AdvancedPolicyAnalyzer]::new($script:DefaultMockPolicies, $script:DefaultSignInLogs, $script:DefaultAuditLogs, $script:DefaultUserGroupMap)
            $analyzer.Should().Not().BeNull()
            $analyzer.AllPolicies.Should().BeEquivalentTo($script:DefaultMockPolicies)
            $analyzer.SignInLogs.Should().BeEquivalentTo($script:DefaultSignInLogs)
            $analyzer.AuditLogs.Should().BeEquivalentTo($script:DefaultAuditLogs)
            $analyzer.UserGroupMembershipMap.Should().BeEquivalentTo($script:DefaultUserGroupMap)
            $script:CapturedVerboseMessages.Should().ContainMatch("User group membership map provided")
        }

        It 'Warns if input policies array is null' {
            $analyzer = [AdvancedPolicyAnalyzer]::new($null, $script:DefaultSignInLogs, $script:DefaultAuditLogs, $null)
            $script:CapturedWarnings.Should().ContainMatch("AdvancedPolicyAnalyzer initialized with no policies.")
        }

        It 'Warns if input policies array is empty' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@(), $script:DefaultSignInLogs, $script:DefaultAuditLogs, $null)
            $script:CapturedWarnings.Should().ContainMatch("AdvancedPolicyAnalyzer initialized with no policies.")
        }

        It 'Warns if input policies array seems to contain non-policy objects (e.g. missing Id)' {
            $nonPolicyObject = @([pscustomobject]@{ SomethingElse = "value" })
            $analyzer = [AdvancedPolicyAnalyzer]::new($nonPolicyObject, $script:DefaultSignInLogs, $script:DefaultAuditLogs, $null)
            $script:CapturedWarnings.Should().ContainMatch("AdvancedPolicyAnalyzer initialized with an array that does not appear to contain valid policy objects .* missing Id or DisplayName")
        }

        It 'Logs verbose message if UserGroupMap is provided' {
            $analyzer = [AdvancedPolicyAnalyzer]::new($script:DefaultMockPolicies, $script:DefaultSignInLogs, $script:DefaultAuditLogs, $script:DefaultUserGroupMap)
            $script:CapturedVerboseMessages.Should().ContainMatch("User group membership map provided with \d+ entries.")
        }

        It 'Logs verbose message if UserGroupMap is NOT provided' {
            $analyzer = [AdvancedPolicyAnalyzer]::new($script:DefaultMockPolicies, $script:DefaultSignInLogs, $script:DefaultAuditLogs, $null)
            $script:CapturedVerboseMessages.Should().ContainMatch("No user group membership map provided.")
        }
    }

    Context 'GeneratePolicyOverlapReport Method' {
        $policyAllUsersAllApps1 = $script:NewMockCaPolicy -Id "P_AU_AA_1" -DisplayName "All Users All Apps 1" `
                                                        -Users @{ IncludeUsers = @("All") } `
                                                        -Applications @{ IncludeApplications = @("All") } `
                                                        -GrantControls @{ Operator = "OR"; BuiltInControls = @("mfa") }
        $policyAllUsersAllApps2 = $script:NewMockCaPolicy -Id "P_AU_AA_2" -DisplayName "All Users All Apps 2" `
                                                        -Users @{ IncludeUsers = @("All") } `
                                                        -Applications @{ IncludeApplications = @("All") } `
                                                        -GrantControls @{ Operator = "AND"; BuiltInControls = @("compliantDevice") }

        $policySpecificUser1App1 = $script:NewMockCaPolicy -Id "P_U1_A1" -DisplayName "User1 App1 Policy" `
                                                        -Users @{ IncludeUsers = @("user1@contoso.com"); IncludeGroups=@("group1") } `
                                                        -Applications @{ IncludeApplications = @("app1-id") } `
                                                        -GrantControls @{ Operator = "OR"; BuiltInControls = @("mfa") }

        $policySpecificUser2App2 = $script:NewMockCaPolicy -Id "P_U2_A2" -DisplayName "User2 App2 Policy" `
                                                        -Users @{ IncludeUsers = @("user2@contoso.com"); IncludeGroups=@("group2") } `
                                                        -Applications @{ IncludeApplications = @("app2-id") }

        $policyUser1AppX = $script:NewMockCaPolicy -Id "P_U1_AX" -DisplayName "User1 AppX Policy" `
                                                -Users @{ IncludeUsers = @("user1@contoso.com") } `
                                                -Applications @{ IncludeApplications = @("appX-id") }

        $policyDisabled = $script:NewMockCaPolicy -Id "P_Disabled" -DisplayName "Disabled Policy" -State "disabled"

        It 'Returns empty OverlapSets if fewer than two active policies are provided' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyAllUsersAllApps1), @(), @())
            $report = $analyzer.GeneratePolicyOverlapReport()
            $report.OverlapSets.Should().BeEmpty()

            $analyzer2 = [AdvancedPolicyAnalyzer]::new(@($policyAllUsersAllApps1, $policyDisabled), @(), @()) # Only one active
            $report2 = $analyzer2.GeneratePolicyOverlapReport()
            $report2.OverlapSets.Should().BeEmpty()
        }

        It 'Returns empty OverlapSets if no policies overlap in both user and application conditions' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policySpecificUser1App1, $policySpecificUser2App2), @(), @())
            $report = $analyzer.GeneratePolicyOverlapReport()
            $report.OverlapSets.Should().BeEmpty()
        }

        It 'Identifies Full User and Full Application overlap (All vs All)' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyAllUsersAllApps1, $policyAllUsersAllApps2), @(), @())
            $report = $analyzer.GeneratePolicyOverlapReport()
            $report.OverlapSets.Should().HaveCount(1)
            $set = $report.OverlapSets[0]
            $set.Policies.Should().ContainMatch("*$($policyAllUsersAllApps1.DisplayName)*")
            $set.Policies.Should().ContainMatch("*$($policyAllUsersAllApps2.DisplayName)*")
            $set.UserOverlapType.Should().Be('Full (All Users vs All Users)') # From refined helper
            $set.AppOverlapType.Should().Be('Full (All Apps vs All Apps)')   # From refined helper
            $set.CombinedGrantControls.Should().Contain("Policy A: Operator 'OR', Controls 'mfa'")
            $set.CombinedGrantControls.Should().Contain("Policy B: Operator 'AND', Controls 'compliantDevice'")
        }

        It 'Identifies Subset User overlap (All vs Specific) and Subset App overlap (All vs Specific)' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyAllUsersAllApps1, $policySpecificUser1App1), @(), @())
            $report = $analyzer.GeneratePolicyOverlapReport()
            $report.OverlapSets.Should().HaveCount(1)
            $set = $report.OverlapSets[0]
            $set.UserOverlapType.Should().Be('Subset (All Users vs Specific)')
            $set.AppOverlapType.Should().Be('Subset (All Apps vs Specific)')
        }

        It 'Does not report overlap if only User conditions overlap but Apps do not' {
             $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyAllUsersAllApps1, $policySpecificUser2App2), @(), @())
             # P_AU_AA_1 is All Users / All Apps. P_U2_A2 is Specific User2 / Specific App2.
             # User overlap will be Subset. App overlap will be Subset. So this WILL report.
             # Let's make P_U2_A2 use an app that P_AU_AA_1 excludes for a better test of "no app overlap"
             $policyAllUsersAllAppsWithExclusion = $script:NewMockCaPolicy -Id "P_AU_AA_EXCL" -DisplayName "All Users All Apps Excl App2" `
                                                        -Users @{ IncludeUsers = @("All") } `
                                                        -Applications @{ IncludeApplications = @("All"); ExcludeApplications = @("app2-id") }

            $analyzer2 = [AdvancedPolicyAnalyzer]::new(@($policyAllUsersAllAppsWithExclusion, $policySpecificUser2App2), @(), @())
            $report2 = $analyzer2.GeneratePolicyOverlapReport()
            # User Overlap: Subset (All Users vs Specific)
            # App Overlap: None (because app2-id is excluded by the 'All Apps' policy)
            $report2.OverlapSets.Should().BeEmpty("Overlap should not be reported if app conditions result in no overlap due to exclusion.")
        }

        It 'Does not report overlaps involving disabled policies' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyAllUsersAllApps1, $policyDisabled), @(), @())
            $report = $analyzer.GeneratePolicyOverlapReport()
            $report.OverlapSets.Should().BeEmpty()
        }
    }

    Context 'AnalyzePolicyCoverage Method' {
        $user1 = "user1@example.com"
        $user2 = "user2@example.com"
        $guestUser = "guest_user#EXT#@example.com"

        $app1Id = "app1-guid"
        $app2Id = "app2-guid"
        # $allAppsKeyword = "All" # Already used by default in NewMockCaPolicy for Applications.IncludeApplications

        $group1Id = "group1-guid"
        $group2Id = "group2-guid"

        $mockUserGroupMap = @{
            ($user1) = @($group1Id)
            ($user2) = @($group2Id)
            ($guestUser) = @()
        }

        # Define policies for coverage scenarios
        $policyDirectUser1MFA = $script:NewMockCaPolicy -Id "Cov_User1_Direct_MFA" -DisplayName "Direct UPN for User1 (MFA)" -Users @{ IncludeUsers = @($user1) } -GrantControls @{Operator="OR"; BuiltInControls=@("mfa")}
        $policyAllUsersCompliant = $script:NewMockCaPolicy -Id "Cov_AllUsers_Compliant" -DisplayName "All Users Policy (Compliant)" -Users @{ IncludeUsers = @("All") } -GrantControls @{Operator="OR"; BuiltInControls=@("compliantDevice")}
        $policyExcludeUser1AllUsers = $script:NewMockCaPolicy -Id "Cov_All_Exclude_User1" -DisplayName "All Users Exclude User1" -Users @{ IncludeUsers = @("All"); ExcludeUsers = @($user1) }

        $policyGroup1MFA = $script:NewMockCaPolicy -Id "Cov_Group1_MFA" -DisplayName "Group1 Policy (MFA)" -Users @{ IncludeGroups = @($group1Id) } -GrantControls @{Operator="OR"; BuiltInControls=@("mfa")}
        $policyInclG1ExclG1 = $script:NewMockCaPolicy -Id "Cov_G1_Excl_G1" -DisplayName "Incl G1 Excl G1" -Users @{ IncludeGroups = @($group1Id); ExcludeGroups = @($group1Id) }

        $policyDisabledUser1 = $script:NewMockCaPolicy -Id "Cov_Disabled_User1" -DisplayName "Disabled User1 Policy" -Users @{ IncludeUsers = @($user1) } -State "disabled"

        $policyDirectApp1Compliant = $script:NewMockCaPolicy -Id "Cov_App1_Direct_Compliant" -DisplayName "Direct App1 Policy (Compliant)" -Applications @{ IncludeApplications = @($app1Id) } -GrantControls @{Operator="OR"; BuiltInControls=@("compliantDevice")}
        $policyAllAppsMFA = $script:NewMockCaPolicy -Id "Cov_AllApps_MFA" -DisplayName "All Apps Policy (MFA)" -Applications @{ IncludeApplications = @("All") } -GrantControls @{Operator="OR"; BuiltInControls=@("mfa")}
        $policyExcludeApp1AllApps = $script:NewMockCaPolicy -Id "Cov_All_Exclude_App1" -DisplayName "All Apps Exclude App1" -Applications @{ IncludeApplications = @("All"); ExcludeApplications = @($app1Id) }

        $policyBlockUser1App1 = $script:NewMockCaPolicy -Id "Cov_Block_U1_A1" -DisplayName "Block User1 App1" -Users @{IncludeUsers=@($user1)} -Applications @{IncludeApplications=@($app1Id)} -GrantControls @{Operator="OR"; BuiltInControls=@("block")}


        It 'Returns empty coverage if no active policies exist or no policies loaded' {
            $analyzerNoPolicies = [AdvancedPolicyAnalyzer]::new(@(), @(), @(), $null) # No policies loaded
            $reportNoPolicies = $analyzerNoPolicies.AnalyzePolicyCoverage(@($user1), @($app1Id))
            $reportNoPolicies.UserCoverage[0].IsCovered.Should().BeFalse()
            $reportNoPolicies.ApplicationCoverage[0].IsCovered.Should().BeFalse()
            $script:CapturedWarnings.Should().ContainMatch("No policies loaded into AdvancedPolicyAnalyzer.")

            $script:CapturedWarnings.Clear() # Clear for next check
            $analyzerDisabled = [AdvancedPolicyAnalyzer]::new(@($policyDisabledUser1), @(), @(), $null)
            $reportDisabled = $analyzerDisabled.AnalyzePolicyCoverage(@($user1), @($app1Id))
            $reportDisabled.UserCoverage[0].IsCovered.Should().BeFalse()
            $script:CapturedWarnings.Should().ContainMatch("No active .* policies found. Coverage will be zero.")
        }

        It 'Correctly reports a critical user covered by a direct UPN assignment' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyDirectUser1MFA), @(), @(), $null)
            $report = $analyzer.AnalyzePolicyCoverage(@($user1), @())
            $userReport = $report.UserCoverage[0]
            $userReport.IsCovered.Should().BeTrue()
            $userReport.AppliedPolicyCount.Should().Be(1)
            $userReport.Policies.Should().Be($policyDirectUser1MFA.DisplayName)
            $userReport.EffectiveControlsSummary.Should().Be("Requires: mfa (Operators involved: OR)")
        }

        It 'Correctly reports a critical user covered by an "All Users" policy' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyAllUsersCompliant), @(), @(), $null)
            $report = $analyzer.AnalyzePolicyCoverage(@($user2), @())
            $userReport = $report.UserCoverage[0]
            $userReport.IsCovered.Should().BeTrue()
            $userReport.Policies.Should().Be($policyAllUsersCompliant.DisplayName)
            $userReport.EffectiveControlsSummary.Should().Be("Requires: compliantDevice (Operators involved: OR)")
        }

        It 'Correctly reports a critical user NOT covered if excluded by UPN from an "All Users" policy' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyExcludeUser1AllUsers),@(),@())
            $report = $analyzer.AnalyzePolicyCoverage(@($user1),@())
            $report.UserCoverage[0].IsCovered.Should().BeFalse("User1 should be excluded by policy $($policyExcludeUser1AllUsers.DisplayName)")
        }

        It 'Correctly reports a critical user covered by a group assignment (with UserGroupMap)' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyGroup1MFA), @(), @(), $mockUserGroupMap)
            $report = $analyzer.AnalyzePolicyCoverage(@($user1), @()) # user1 is in group1Id via map
            $userReport = $report.UserCoverage[0]
            $userReport.IsCovered.Should().BeTrue()
            $userReport.Policies.Should().Be($policyGroup1MFA.DisplayName)
            $userReport.EffectiveControlsSummary.Should().Be("Requires: mfa (Operators involved: OR)")
        }

        It 'Correctly reports user NOT covered if in an excluded group of a group-targeting policy' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyInclG1ExclG1), @(), @(), $mockUserGroupMap) # Policy targets Group1, Excludes Group1
            $report = $analyzer.AnalyzePolicyCoverage(@($user1), @()) # user1 is in Group1
            $report.UserCoverage[0].IsCovered.Should().BeFalse()
        }

        It 'Reports user as not covered by group policy if UserGroupMap is missing or user not in map' {
            $analyzerNoMap = [AdvancedPolicyAnalyzer]::new(@($policyGroup1MFA), @(), @(), $null) # No map
            $reportNoMap = $analyzerNoMap.AnalyzePolicyCoverage(@("unknownUser@example.com"), @())
            $reportNoMap.UserCoverage[0].IsCovered.Should().BeFalse()
            $script:CapturedVerboseMessages.Should().ContainMatch("No pre-loaded group membership context found for user 'unknownUser@example.com'")
        }

        It 'Correctly reports a critical application covered by a direct App ID assignment' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyDirectApp1Compliant), @(), @(), $null)
            $report = $analyzer.AnalyzePolicyCoverage(@(), @($app1Id))
            $appReport = $report.ApplicationCoverage[0]
            $appReport.IsCovered.Should().BeTrue()
            $appReport.Policies.Should().Be($policyDirectApp1Compliant.DisplayName)
            $appReport.EffectiveControlsSummary.Should().Be("Requires: compliantDevice (Operators involved: OR)")
        }

        It 'Correctly reports a critical application covered by an "All Applications" policy' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyAllAppsMFA), @(), @(), $null)
            $report = $analyzer.AnalyzePolicyCoverage(@(), @($app2Id)) # app2Id should be covered
            $appReport = $report.ApplicationCoverage[0]
            $appReport.IsCovered.Should().BeTrue()
            $appReport.Policies.Should().Be($policyAllAppsMFA.DisplayName)
            $appReport.EffectiveControlsSummary.Should().Be("Requires: mfa (Operators involved: OR)")
        }

        It 'Correctly reports a critical application NOT covered if excluded from "All Applications" policy' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyExcludeApp1AllApps), @(), @(), $null)
            $report = $analyzer.AnalyzePolicyCoverage(@(), @($app1Id))
            $report.ApplicationCoverage[0].IsCovered.Should().BeFalse()
        }

        It 'Correctly reports a user covered by multiple policies and summarizes controls' {
            $policies = @($policyDirectUser1MFA, $policyGroup1MFA, $policyAllUsersCompliant)
            # User1 is directly included in policyDirectUser1MFA
            # User1 is in Group1 (via mockUserGroupMap), so policyGroup1MFA applies
            # User1 is covered by policyAllUsersCompliant
            $analyzer = [AdvancedPolicyAnalyzer]::new($policies, @(), @(), $mockUserGroupMap)
            $report = $analyzer.AnalyzePolicyCoverage(@($user1), @())

            $user1Report = $report.UserCoverage[0]
            $user1Report.IsCovered.Should().BeTrue()
            $user1Report.AppliedPolicyCount.Should().Be(3)
            $user1Report.Policies.Should().Be("$($policyDirectUser1MFA.DisplayName); $($policyGroup1MFA.DisplayName); $($policyAllUsersCompliant.DisplayName)")
            $user1Report.EffectiveControlsSummary.Should().Be("Requires: compliantDevice, mfa (Operators involved: OR, OR, OR)")
        }

        It 'Correctly reports "Blocked" as effective control if one of multiple applying policies blocks access' {
            $policies = @($policyDirectUser1MFA, $policyBlockUser1App1)
            # Test for user1 coverage. policyDirectUser1MFA applies. policyBlockUser1App1 also applies to user1.
            $analyzer = [AdvancedPolicyAnalyzer]::new($policies, @(), @(), $null)
            $report = $analyzer.AnalyzePolicyCoverage(@($user1), @())
            $user1Report = $report.UserCoverage[0]
            $user1Report.IsCovered.Should().BeTrue()
            $user1Report.AppliedPolicyCount.Should().Be(2) # Both policies apply to user1
            $user1Report.EffectiveControlsSummary.Should().Be("Blocked (by '$($policyBlockUser1App1.DisplayName)')")
        }

        It 'Handles critical users/apps lists being empty or null' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyAllUsersAllApps1), @(), @(), $null)
            $reportEmpty = $analyzer.AnalyzePolicyCoverage(@(), @())
            $reportEmpty.UserCoverage.Should().BeEmpty()
            $reportEmpty.ApplicationCoverage.Should().BeEmpty()

            $reportNull = $analyzer.AnalyzePolicyCoverage($null, $null)
            $reportNull.UserCoverage.Should().BeEmpty()
            $reportNull.ApplicationCoverage.Should().BeEmpty()
        }

        It 'Produces the correct output structure for UserCoverage and ApplicationCoverage items' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($policyDirectUser1MFA), @(), @(), $null)
            $report = $analyzer.AnalyzePolicyCoverage(@($user1), @())
            $report.UserCoverage[0].PSObject.Properties.Name.Should().BeEquivalentTo(@("UserUPN", "IsCovered", "AppliedPolicyCount", "EffectiveControlsSummary", "Policies"))

            $analyzerApp = [AdvancedPolicyAnalyzer]::new(@($policyDirectApp1Compliant), @(),@(), $null)
            $reportApp = $analyzerApp.AnalyzePolicyCoverage(@(), @($app1Id))
            $reportApp.ApplicationCoverage[0].PSObject.Properties.Name.Should().BeEquivalentTo(@("Application", "IsCovered", "AppliedPolicyCount", "EffectiveControlsSummary", "Policies"))
        }
    }

    Context 'GeneratePolicyChangeImpactAnalysis Method' {
        $testPolicyId = "policy-id-1"
        $testPolicyDisplayName = "Test Policy For Impact"
        $mockTestPolicy = $script:NewMockCaPolicy -Id $testPolicyId -DisplayName $testPolicyDisplayName

        # Define fixed dates for consistent test windows
        $script:FixedCurrentDate = Get-Date "2023-07-01T10:00:00Z" # Anchor date for tests
        $changeDate = $script:FixedCurrentDate.AddDays(-10)
        $daysWindow = 7

        # Helpers for mock logs need to be available if not in BeforeAll
        if (-not $script:NewMockSignInLog) { # Define if not already in BeforeAll from a previous test file creation
            $script:NewMockSignInLog = {
                param(
                    [datetime]$CreatedDateTime = (Get-Date), [string]$UserPrincipalName = "user@test.com",
                    [string]$AppDisplayName = "Test App", [int]$ErrorCode = 0,
                    [array]$AppliedConditionalAccessPolicies = @()
                )
                return [pscustomobject]@{ CreatedDateTime = $CreatedDateTime; UserPrincipalName = $UserPrincipalName; AppDisplayName = $AppDisplayName; Status = [pscustomobject]@{ ErrorCode = $ErrorCode }; AppliedConditionalAccessPolicies = $AppliedConditionalAccessPolicies | ForEach-Object { [pscustomobject]$_ } }
            }
        }
        if (-not $script:NewMockAuditLog) {
             $script:NewMockAuditLog = {
                param(
                    [string]$PolicyIdTarget, [datetime]$ActivityDateTime = (Get-Date),
                    [string]$OperationType = "Update policy", [string]$ActivityDisplayName = "Update policy",
                    [string]$ActorUserPrincipalName = "admin@test.com", [array]$ModifiedProperties = @()
                )
                return [pscustomobject]@{ ActivityDateTime = $ActivityDateTime; OperationType = $OperationType; ActivityDisplayName = $ActivityDisplayName; InitiatedBy = [pscustomobject]@{ User = [pscustomobject]@{ UserPrincipalName = $ActorUserPrincipalName }; App = $null }; TargetResources = @( [pscustomobject]@{ Id = $PolicyIdTarget; ModifiedProperties = $ModifiedProperties | ForEach-Object { [pscustomobject]$_ } } ) }
            }
        }

        $mockSignInLogs = @()
        $mockAuditLogs = @()

        BeforeEach {
            $mockSignInLogs = @(
                # Before period: changeDate is 2023-06-21. Window is 7 days. Before is 2023-06-14 to 2023-06-20T23:59:59
                $script:NewMockSignInLog -CreatedDateTime $changeDate.AddDays(-5) -UserPrincipalName "userA@test.com" -AppliedConditionalAccessPolicies @( @{ Id = $testPolicyId; EnforcedGrantControls = @("mfa") } ) # Day -5 = Jun 16
                $script:NewMockSignInLog -CreatedDateTime $changeDate.AddDays(-3) -UserPrincipalName "userB@test.com" -AppliedConditionalAccessPolicies @( @{ Id = $testPolicyId } ) -ErrorCode 50076 # Day -3 = Jun 18 (Failed)
                $script:NewMockSignInLog -CreatedDateTime $changeDate.AddDays(-1) -UserPrincipalName "userC@test.com" -AppliedConditionalAccessPolicies @( @{ Id = "other-policy" } ) # Day -1 = Jun 20 (Not relevant policy)
                # After period: changeDate is 2023-06-21. Window is 7 days. After is 2023-06-21 to 2023-06-28T23:59:59
                $script:NewMockSignInLog -CreatedDateTime $changeDate.AddDays(1) -UserPrincipalName "userA@test.com" -AppliedConditionalAccessPolicies @( @{ Id = $testPolicyId } ) # Day +1 = Jun 22
                $script:NewMockSignInLog -CreatedDateTime $changeDate.AddDays(3) -UserPrincipalName "userB@test.com" -AppliedConditionalAccessPolicies @( @{ Id = $testPolicyId; EnforcedGrantControls = @("mfa") } ) # Day +3 = Jun 24
                $script:NewMockSignInLog -CreatedDateTime $changeDate.AddDays(5) -UserPrincipalName "userC@test.com" -AppliedConditionalAccessPolicies @( @{ Id = $testPolicyId; EnforcedGrantControls = @("mfa") } ) -ErrorCode 53003 # Day +5 = Jun 26 (Failed)
            )

            $mockAuditLogs = @(
                $script:NewMockAuditLog -PolicyIdTarget $testPolicyId -ActivityDateTime $changeDate.AddHours(-1) -OperationType "Update policy" -ActivityDisplayName "Update policy" -ActorUserPrincipalName "admin@test.com" -ModifiedProperties @( @{DisplayName="State"; OldValue="enabled"; NewValue="disabled"}, @{DisplayName="DisplayName"; OldValue=$testPolicyDisplayName; NewValue=$testPolicyDisplayName} )
                $script:NewMockAuditLog -PolicyIdTarget "other-policy" -ActivityDateTime $changeDate.AddDays(-1)
            )
            $script:CapturedWarnings.Clear()
        }

        It 'Returns error report if SignInLogs are not provided to constructor' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($mockTestPolicy), $null, $mockAuditLogs)
            $report = $analyzer.GeneratePolicyChangeImpactAnalysis($testPolicyId, $changeDate, $daysWindow)
            $report.Error.Should().Be("SignInLogs or AuditLogs not available.")
            $script:CapturedWarnings.Should().ContainMatch("SignInLogs or AuditLogs not available/populated")
        }

        It 'Returns error report if AuditLogs are not provided to constructor' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($mockTestPolicy), $mockSignInLogs, $null)
            $report = $analyzer.GeneratePolicyChangeImpactAnalysis($testPolicyId, $changeDate, $daysWindow)
            $report.Error.Should().Be("SignInLogs or AuditLogs not available.")
            $script:CapturedWarnings.Should().ContainMatch("SignInLogs or AuditLogs not available/populated")
        }

        It 'Handles policy ID not found in current policy set by using the ID as name' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@(), $mockSignInLogs, $mockAuditLogs) # Empty policies
            $report = $analyzer.GeneratePolicyChangeImpactAnalysis("unknown-policy-id", $changeDate, $daysWindow)
            $report.PolicyName.Should().Be("Unknown (ID: unknown-policy-id)")
            $script:CapturedWarnings.Should().ContainMatch("Policy with ID unknown-policy-id not found")
        }

        It 'Handles no relevant audit log entry found for the policy change' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($mockTestPolicy), $mockSignInLogs, @( $script:NewMockAuditLog -PolicyIdTarget "other-policy-id" -ActivityDateTime $changeDate.AddHours(-2) ) )
            $report = $analyzer.GeneratePolicyChangeImpactAnalysis($testPolicyId, $changeDate, $daysWindow)
            $report.ChangeAuditEvent.Should().Be("No specific audit log entry found for this policy ID around the change date.")
        }

        It 'Correctly extracts and summarizes ModifiedProperties from audit log' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($mockTestPolicy), $mockSignInLogs, $mockAuditLogs)
            $report = $analyzer.GeneratePolicyChangeImpactAnalysis($testPolicyId, $changeDate, $daysWindow)
            $report.ChangeAuditEvent.Should().Contain("Audit: 'Update policy' by admin@test.com at ")
            $report.ChangeAuditEvent.Should().Contain(". Modified Properties: State, DisplayName")
        }

        It 'Handles audit log entry for "Update policy" with no ModifiedProperties data' {
             $auditLogNoModProps = @(
                $script:NewMockAuditLog -PolicyIdTarget $testPolicyId -ActivityDateTime $changeDate.AddHours(-1) -OperationType "Update policy" -ActivityDisplayName "Update policy" -ModifiedProperties @()
            )
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($mockTestPolicy), $mockSignInLogs, $auditLogNoModProps)
            $report = $analyzer.GeneratePolicyChangeImpactAnalysis($testPolicyId, $changeDate, $daysWindow)
            $report.ChangeAuditEvent.Should().Contain(". Audit log indicates an update, but no specific modified properties were detailed in this log entry view.")
        }

        It 'Returns report indicating no impact if no sign-in logs had the policy applied' {
            $signInLogsNoApplied = @(
                $script:NewMockSignInLog -AppliedConditionalAccessPolicies @(@{Id = "some-other-policy-id"})
            )
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($mockTestPolicy), $signInLogsNoApplied, $mockAuditLogs)
            $report = $analyzer.GeneratePolicyChangeImpactAnalysis($testPolicyId, $changeDate, $daysWindow)
            $report.ImpactSummary.Should().Be("No sign-in logs found where this policy was applied within the loaded SignInLogs.")
            $script:CapturedWarnings.Should().ContainMatch("No sign-in logs found where policy '$($testPolicyDisplayName)' .* was applied.")
        }

        It 'Calculates metrics correctly for "before" and "after" periods' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($mockTestPolicy), $mockSignInLogs, $mockAuditLogs)
            $report = $analyzer.GeneratePolicyChangeImpactAnalysis($testPolicyId, $changeDate, $daysWindow)

            $report.BeforePeriodMetrics.TotalSignIns.Should().Be(2)
            $report.BeforePeriodMetrics.SuccessfulSignIns.Should().Be(1)
            $report.BeforePeriodMetrics.FailedSignIns.Should().Be(1)
            $report.BeforePeriodMetrics.SuccessRate.Should().Be(50.0)
            $report.BeforePeriodMetrics.MfaChallengesByThisPolicy.Should().Be(1)

            $report.AfterPeriodMetrics.TotalSignIns.Should().Be(3)
            $report.AfterPeriodMetrics.SuccessfulSignIns.Should().Be(2)
            $report.AfterPeriodMetrics.FailedSignIns.Should().Be(1)
            $report.AfterPeriodMetrics.SuccessRate.Should().BeApproximately(66.67, 0.01)
            $report.AfterPeriodMetrics.MfaChallengesByThisPolicy.Should().Be(2)
        }

        It 'Generates correct ImpactSummary string based on metric changes' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($mockTestPolicy), $mockSignInLogs, $mockAuditLogs)
            $report = $analyzer.GeneratePolicyChangeImpactAnalysis($testPolicyId, $changeDate, $daysWindow)
            $report.ImpactSummary.Should().Be("Sign-in success rate changed from 50% (of 2 sign-ins) to 66.67% (of 3 sign-ins). MFA challenges specifically by this policy changed from 1 to 2.")
        }

        It 'Handles periods with no relevant sign-ins gracefully in metrics and summary' {
            $signInLogsOnlyBefore = @(
                $script:NewMockSignInLog -CreatedDateTime $changeDate.AddDays(-1) -AppliedConditionalAccessPolicies @( @{ Id = $testPolicyId } )
            )
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($mockTestPolicy), $signInLogsOnlyBefore, $mockAuditLogs)
            $report = $analyzer.GeneratePolicyChangeImpactAnalysis($testPolicyId, $changeDate, $daysWindow)
            $report.BeforePeriodMetrics.TotalSignIns.Should().Be(1)
            $report.AfterPeriodMetrics.TotalSignIns.Should().Be(0)
            $report.ImpactSummary.Should().Be("No sign-in activity (where this policy applied) found in the 'after' period. Before change: Success Rate 100%, MFA by this policy: 0.")
        }

        It 'Produces the correct overall output structure for the impact report' {
            $analyzer = [AdvancedPolicyAnalyzer]::new(@($mockTestPolicy), $mockSignInLogs, $mockAuditLogs)
            $report = $analyzer.GeneratePolicyChangeImpactAnalysis($testPolicyId, $changeDate, $daysWindow)
            $report.PSObject.Properties.Name.Should().BeEquivalentTo(@(
                "PolicyName", "PolicyId", "ChangeDate", "ChangeAuditEvent", "AnalysisWindowDays",
                "MetricsTimeWindow", "BeforePeriodMetrics", "AfterPeriodMetrics", "ImpactSummary", "Note"
            ))
            $report.MetricsTimeWindow.PSObject.Properties.Name.Should().BeEquivalentTo(@(
                "BeforePeriod_Start", "BeforePeriod_End", "AfterPeriod_Start", "AfterPeriod_End"
            ))
            $report.BeforePeriodMetrics.PSObject.Properties.Name.Should().BeEquivalentTo(@(
                "TotalSignIns", "SuccessfulSignIns", "FailedSignIns", "SuccessRate", "MfaChallengesByThisPolicy"
            ))
        }
    }
}
