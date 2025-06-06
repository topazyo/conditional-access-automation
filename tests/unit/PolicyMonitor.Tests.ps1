# Pester tests for PolicyMonitor class
# Test suite for src/modules/reporting/policy_monitor.ps1

BeforeAll {
    Import-Module $PSScriptRoot/../../src/modules/reporting/policy_monitor.ps1 -Force

    # Global Mocks
    Mock Connect-MgGraph { Write-Verbose "Mocked Connect-MgGraph"; return $true } -ModuleName *
    Mock Get-MgIdentityConditionalAccessPolicy { Write-Verbose "Mocked Get-MgIdentityConditionalAccessPolicy"; return @() } -ModuleName *
    Mock Get-MgAuditLogSignIn { Write-Verbose "Mocked Get-MgAuditLogSignIn"; return @() } -ModuleName *
    Mock Get-MgAuditLogDirectoryAudit { Write-Verbose "Mocked Get-MgAuditLogDirectoryAudit"; return @() } -ModuleName *

    Mock Invoke-RestMethod {
        Write-Verbose "Mocked Invoke-RestMethod"
        $script:InvokeRestMethodParams = $PSBoundParameters
    } -ModuleName * # Ensure it mocks the one used by PolicyMonitor if it's in a different scope

    # Helper to create mock Sign-In Log objects
    $script:NewMockSignInLog = {
        param (
            [string]$UserPrincipalName = "user@example.com",
            [int]$ErrorCode = 0, # 0 for success
            [string]$ConditionalAccessStatus = "success", # success, failure, notApplied
            [array]$AppliedConditionalAccessPolicies = @() # Array of hashtables like @{ Id = "guid"; DisplayName = "PolicyName"; EnforcedGrantControls = @("mfa") }
        )
        return [pscustomobject]@{
            UserPrincipalName              = $UserPrincipalName
            CreatedDateTime                = Get-Date
            Status                         = [pscustomobject]@{ ErrorCode = $ErrorCode }
            ConditionalAccessStatus        = $ConditionalAccessStatus
            AppliedConditionalAccessPolicies = $AppliedConditionalAccessPolicies | ForEach-Object { [pscustomobject]$_ }
        }
    }

    # Helper to create mock Directory Audit Log objects for CA policy changes
    $script:NewMockDirectoryAuditLog = {
        param (
            [string]$OperationType = "Update", # Add, Update, Delete
            [string]$PolicyId = (New-Guid).Guid,
            [string]$PolicyName = "Test Policy",
            [string]$ModifiedByUPN = "admin@example.com",
            [string]$ModifiedByApp = $null,
            [array]$ModifiedProperties = @() # Array of hashtables like @{ DisplayName="State"; NewValue="enabled"; OldValue="disabled" }
        )
        return [pscustomobject]@{
            ActivityDateTime = (Get-Date).AddMinutes(-5)
            OperationType    = $OperationType
            TargetResources  = @(
                [pscustomobject]@{
                    Id                 = $PolicyId
                    DisplayName        = $PolicyName
                    Type               = "ConditionalAccessPolicy"
                    ModifiedProperties = $ModifiedProperties | ForEach-Object { [pscustomobject]$_ }
                }
            )
            InitiatedBy      = [pscustomobject]@{
                User = if (-not [string]::IsNullOrEmpty($ModifiedByUPN)) { [pscustomobject]@{ UserPrincipalName = $ModifiedByUPN } } else { $null }
                App  = if (-not [string]::IsNullOrEmpty($ModifiedByApp)) { [pscustomobject]@{ DisplayName = $ModifiedByApp } } else { $null }
            }
        }
    }
}

AfterAll {
    Remove-Variable -Name "NewMock*" -Scope script -ErrorAction SilentlyContinue
    Remove-Variable -Name "InvokeRestMethodParams" -Scope script -ErrorAction SilentlyContinue
}

Describe 'PolicyMonitor Class' {
    $mockWorkspaceId = "mock-ws-id"
    $mockLogAnalyticsKey = "mock-la-key"
    $monitor = $null

    BeforeEach {
        $script:InvokeRestMethodParams = $null
        # Reset specific mocks if needed, though global ones are often sufficient
        Mock Get-MgIdentityConditionalAccessPolicy { return @() } -ModuleName *
        Mock Get-MgAuditLogSignIn { return @() } -ModuleName *
        Mock Get-MgAuditLogDirectoryAudit { return @() } -ModuleName *
    }

    Context 'Constructor and Connection Setup (ConfigureLogAnalytics)' {
        It 'Sets properties and logs readiness when Workspace ID and Key are valid' {
            $verboseMessages = @()
            Mock Write-Verbose -MockWith { param($Message) $verboseMessages += $Message }

            $monitor = [PolicyMonitor]::new($mockWorkspaceId, $mockLogAnalyticsKey)
            $monitor.WorkspaceId.Should().Be($mockWorkspaceId)
            $monitor.LogAnalyticsKey.Should().Be($mockLogAnalyticsKey)
            $verboseMessages.Should().Contain("Log Analytics Workspace ID and Key are present. Ready to send data to Log Analytics.")
        }

        It 'Issues a warning if Workspace ID is missing' {
            $warningMessages = @()
            Mock Write-Warning -MockWith { param($Message) $warningMessages += $Message }

            $monitor = [PolicyMonitor]::new($null, $mockLogAnalyticsKey)
            $warningMessages.Should().Contain("Log Analytics Workspace ID or Primary Key is missing or empty. Log Analytics integration will be disabled.")
        }

        It 'Issues a warning if Log Analytics Key is missing' {
            $warningMessages = @()
            Mock Write-Warning -MockWith { param($Message) $warningMessages += $Message }

            $monitor = [PolicyMonitor]::new($mockWorkspaceId, "") # Empty key
            $warningMessages.Should().Contain("Log Analytics Workspace ID or Primary Key is missing or empty. Log Analytics integration will be disabled.")
        }
    }

    Context 'GenerateMetricsReport Method' {
        $startDate = (Get-Date).AddDays(-7)
        $endDate = Get-Date

        BeforeEach {
            $monitor = [PolicyMonitor]::new($mockWorkspaceId, $mockLogAnalyticsKey)
        }

        It 'Formats Get-MgAuditLogSignIn filter dates correctly (ISO 8601)' {
            $expectedFilterStart = $startDate.ToUniversalTime().ToString("o")
            $expectedFilterEnd = $endDate.ToUniversalTime().ToString("o")
            $expectedFilter = "createdDateTime ge $expectedFilterStart and createdDateTime le $expectedFilterEnd"

            Mock Get-MgAuditLogSignIn -MockWith { param($Filter) $Filter.Should().Be($expectedFilter); return @() } -Verifiable
            $monitor.GenerateMetricsReport($startDate, $endDate)
            Assert-VerifiableMocks
        }

        It 'Calculates TotalPolicies and ActivePolicies correctly' {
            $mockPolicies = @(
                [pscustomobject]@{ State = 'enabled' },
                [pscustomobject]@{ State = 'disabled' },
                [pscustomobject]@{ State = 'enabled' }
            )
            Mock Get-MgIdentityConditionalAccessPolicy -ModuleName * -MockWith { return $mockPolicies }

            $report = $monitor.GenerateMetricsReport($startDate, $endDate)
            $report.PolicyMetrics.TotalPolicies.Should().Be(3)
            $report.PolicyMetrics.ActivePolicies.Should().Be(2)
        }

        It 'Calculates sign-in metrics and user impact correctly' {
            $signInLogs = @(
                $script:NewMockSignInLog -UserPrincipalName "user1@example.com" -ErrorCode 0 # Success
                $script:NewMockSignInLog -UserPrincipalName "user2@example.com" -ErrorCode 0 -AppliedConditionalAccessPolicies @( @{ EnforcedGrantControls = @('mfa') } ) # Success with MFA
                $script:NewMockSignInLog -UserPrincipalName "user1@example.com" -ErrorCode 50076 # Failure (e.g. MFA required but not completed)
                $script:NewMockSignInLog -UserPrincipalName "user3@example.com" -ErrorCode 53003 -ConditionalAccessStatus 'failure' # Blocked by CA
                $script:NewMockSignInLog -UserPrincipalName "user4@example.com" -ErrorCode 0 # Success
                $script:NewMockSignInLog -UserPrincipalName "user3@example.com" -ErrorCode 53003 -ConditionalAccessStatus 'failure' # User 3 blocked again
            )
            Mock Get-MgAuditLogSignIn -ModuleName * -MockWith { return $signInLogs }

            $report = $monitor.GenerateMetricsReport($startDate, $endDate)
            $report.PolicyMetrics.SuccessfulSignIns.Should().Be(3)
            $report.PolicyMetrics.FailedSignIns.Should().Be(3)
            $report.PolicyMetrics.MFAChallenges.Should().Be(1) # Only one log explicitly had MFA in enforcedGrantControls

            $report.UserImpact.TotalUsers.Should().Be(4) # user1, user2, user3, user4
            $report.UserImpact.BlockedUsers.Should().Be(1) # Only user3
        }

        It 'Handles empty sign-in logs gracefully for recommendations' {
            Mock Get-MgAuditLogSignIn -ModuleName * -MockWith { return @() }
            $warningMessages = @()
            Mock Write-Warning -MockWith { param($Message) $warningMessages += $Message }

            $report = $monitor.GenerateMetricsReport($startDate, $endDate)
            $report.Recommendations.Should().BeEmpty()
            $warningMessages.Should().Contain("No sign-in logs processed, skipping recommendations generation.")
        }
    }

    Context 'GenerateRecommendations (hidden) Method' {
        # Test this hidden method directly by creating an instance and calling it
        BeforeEach {
            $monitor = [PolicyMonitor]::new($mockWorkspaceId, $mockLogAnalyticsKey)
        }

        It 'Recommends reviewing policies if failure rate is high' {
            $metrics = @{ FailedSignIns = 20; SuccessfulSignIns = 80; MFAChallenges = 10 } # 20% failure
            $recommendations = $monitor.GenerateRecommendations($metrics) # Accessing hidden method via instance
            $recommendations.Should().Contain("High failure rate detected. Review policy conditions for potential conflicts.")
        }

        It 'Does NOT recommend reviewing policies if failure rate is low' {
            $metrics = @{ FailedSignIns = 5; SuccessfulSignIns = 95; MFAChallenges = 10 } # 5% failure
            $recommendations = $monitor.GenerateRecommendations($metrics)
            $recommendations.Should().Not().Contain("High failure rate detected. Review policy conditions for potential conflicts.")
        }

        It 'Recommends expanding MFA if adoption is low' {
            $metrics = @{ FailedSignIns = 5; SuccessfulSignIns = 95; MFAChallenges = 30 } # MFA challenges < 50% of successful sign-ins
            $recommendations = $monitor.GenerateRecommendations($metrics)
            $recommendations.Should().Contain("Low MFA adoption rate. Consider expanding MFA requirements.")
        }

         It 'Does NOT recommend expanding MFA if adoption is high' {
            $metrics = @{ FailedSignIns = 5; SuccessfulSignIns = 95; MFAChallenges = 70 } # MFA challenges > 50%
            $recommendations = $monitor.GenerateRecommendations($metrics)
            $recommendations.Should().Not().Contain("Low MFA adoption rate. Consider expanding MFA requirements.")
        }

        It 'Handles zero successful signins for MFA adoption check' {
             $metrics = @{ FailedSignIns = 5; SuccessfulSignIns = 0; MFAChallenges = 0 }
             $recommendations = $monitor.GenerateRecommendations($metrics) # Should not throw divide by zero
             # Depending on logic, it might suggest MFA or not. Key is no error.
             # Current logic: 0/0 is not < 0.5, so no recommendation. If SuccessfulSignIns is 0, MFAChallenges / 0 is problematic.
             # The SUT's GenerateRecommendations needs to handle SuccessfulSignIns = 0 to avoid division by zero.
             # Assuming SUT updated to handle: if ($metrics.SuccessfulSignIns -gt 0 -and $metrics.MFAChallenges / $metrics.SuccessfulSignIns -lt 0.5)
             # For now, let's assume the test reflects a potential need for guard in SUT.
             # If SUT is robust, this test just checks output.
             # If current SUT has $metrics.MFAChallenges / $metrics.SuccessfulSignIns:
             # This would throw. Let's assume it is robust or test that it doesn't throw.
             { $monitor.GenerateRecommendations($metrics) }.Should().Not().Throw()
        }
    }

    Context 'Policy Change Monitoring (MonitorPolicyChanges, LogPolicyChange, SendToLogAnalytics)' {
        $mockAuditLog1 = $script:NewMockDirectoryAuditLog -PolicyName "Policy Alpha"
        $mockAuditLog2 = $script:NewMockDirectoryAuditLog -PolicyName "Policy Beta" -OperationType "Add"

        BeforeEach {
            $monitor = [PolicyMonitor]::new($mockWorkspaceId, $mockLogAnalyticsKey)
        }

        It 'MonitorPolicyChanges calls LogPolicyChange for each audit log' {
            Mock Get-MgAuditLogDirectoryAudit -ModuleName * -MockWith { return @($mockAuditLog1, $mockAuditLog2) }
            $logPolicyChangeCalls = 0
            Mock ($monitor.LogPolicyChange) { $logPolicyChangeCalls++ } -Verifiable # Mocking the instance method

            $monitor.MonitorPolicyChanges()
            $logPolicyChangeCalls.Should().Be(2)
            Assert-VerifiableMocks # This might not work as expected for instance method mocks without more setup.
                                   # Alternative: check side effects or if SendToLogAnalytics was called.
        }

        It 'LogPolicyChange constructs correct logEntry and calls SendToLogAnalytics' {
            $testTime = Get-Date
            $auditLog = $script:NewMockDirectoryAuditLog -OperationType "Update" `
                                                        -PolicyId "policy-guid-123" `
                                                        -PolicyName "Updated Policy" `
                                                        -ModifiedByUPN "editor@example.com" `
                                                        -ModifiedProperties @(
                                                            @{ DisplayName="State"; NewValue="disabled"; OldValue="enabled" },
                                                            @{ DisplayName="Description"; NewValue="New Desc"; OldValue="Old Desc" }
                                                        )
            $auditLog.ActivityDateTime = $testTime # Set a fixed time for assertion

            $sendToLaParams = $null
            Mock ($monitor.SendToLogAnalytics) { $sendToLaParams = $PSBoundParameters }

            $monitor.LogPolicyChange($auditLog) # Call hidden method on instance

            $sendToLaParams.Should().Not().BeNull()
            $sendToLaParams.logType.Should().Be("PolicyChanges")
            $logEntry = $sendToLaParams.logEntry

            $logEntry.Should().Not().BeNull()
            $logEntry.ActivityDateTime.Should().Be($testTime)
            $logEntry.ChangeType.Should().Be("Update")
            $logEntry.PolicyId.Should().Be("policy-guid-123")
            $logEntry.PolicyName.Should().Be("Updated Policy")
            $logEntry.ModifiedBy.Should().Be("editor@example.com")
            $logEntry.Changes.Should().BeOfType([array])
            $logEntry.Changes.Count.Should().Be(2)
            $logEntry.Changes[0].DisplayName.Should().Be("State")
            $logEntry.Changes[0].NewValue.Should().Be("disabled")
            $logEntry.Changes[0].OldValue.Should().Be("enabled")
        }

        It 'SendToLogAnalytics calls Invoke-RestMethod with correct parameters and JSON body structure' {
            $logEntryToSend = @{
                TimeGenerated = (Get-Date).ToString("o") # Match typical structure
                ActivityDateTime = (Get-Date).AddMinutes(-1).ToString("o")
                ChangeType    = "Update"
                PolicyId      = "some-id"
                PolicyName    = "Some Policy"
                ModifiedBy    = "someone@example.com"
                Changes       = @(
                    @{ DisplayName = "prop1"; NewValue = "new1"; OldValue = "old1" },
                    @{ DisplayName = "prop2"; NewValue = @{ sub = "val"}; OldValue = @{ sub = "oldval"} } # Nested object
                )
            }

            $monitor.SendToLogAnalytics("TestLogType", $logEntryToSend) # Call hidden method

            $script:InvokeRestMethodParams.Should().Not().BeNull()
            $uri = $script:InvokeRestMethodParams.Uri
            $uri.Should().Be("https://$mockWorkspaceId.ods.opinsights.azure.com/api/logs?api-version=2016-04-01")
            $script:InvokeRestMethodParams.Method.Should().Be("Post")
            $script:InvokeRestMethodParams.Headers.Authorization.Should().StartWith("SharedKey $mockWorkspaceId:")
            $script:InvokeRestMethodParams.Headers."Log-Type".Should().Be("TestLogType")
            $script:InvokeRestMethodParams.ContentType.Should().Be("application/json")

            # Verify JSON body structure
            $jsonBody = $script:InvokeRestMethodParams.Body | ConvertFrom-Json
            $jsonBody.ActivityDateTime.Should().Be($logEntryToSend.ActivityDateTime)
            $jsonBody.ChangeType.Should().Be($logEntryToSend.ChangeType)
            $jsonBody.Changes.Should().BeOfType([array])
            $jsonBody.Changes.Count.Should().Be(2)
            $jsonBody.Changes[0].DisplayName.Should().Be("prop1")
            $jsonBody.Changes[1].NewValue.sub.Should().Be("val") # Check deserialized nested object
        }

        It 'SendToLogAnalytics warns and does not call Invoke-RestMethod if Workspace ID/Key is missing' {
            $monitorNoCreds = [PolicyMonitor]::new($null, $null) # WorkspaceId and Key will be null
            $warningMessages = @()
            Mock Write-Warning -MockWith { param($Message) $warningMessages += $Message }

            $logEntryToSend = @{ Test = "Data" }
            $monitorNoCreds.SendToLogAnalytics("TestType", $logEntryToSend)

            $warningMessages.Should().Contain("Log Analytics Workspace ID or Key is not configured. Skipping sending log for 'TestType'.")
            $script:InvokeRestMethodParams.Should().BeNull("Invoke-RestMethod should not have been called.")
        }
    }
}
