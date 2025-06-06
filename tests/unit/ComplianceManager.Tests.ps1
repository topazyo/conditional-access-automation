# Pester tests for ComplianceManager class
# Test suite for src/modules/compliance/compliance_manager.ps1

BeforeAll {
    Import-Module $PSScriptRoot/../../src/modules/compliance/compliance_manager.ps1 -Force

    # Global Mocks
    Mock Connect-MgGraph {
        Write-Verbose "Mocked Connect-MgGraph called."
        return $true # Simulate successful connection
    } -ModuleName * # Ensure it mocks the one used by ComplianceManager

    Mock Get-MgIdentityConditionalAccessPolicy {
        Write-Verbose "Mocked Get-MgIdentityConditionalAccessPolicy called. Returning default empty array."
        return @()
    } -ModuleName *

    Mock Export-Csv {
        Write-Verbose "Mocked Export-Csv called."
        $script:ExportCsvInputObject = $InputObject
        $script:ExportCsvPath = $Path
        $script:ExportCsvNoTypeInfo = $NoTypeInformation
    } -ModuleName *

    # Helper to create mock policy objects
    $script:NewMockPolicy = {
        param (
            [string]$DisplayName = "Mock Policy",
            [string]$State = "enabled",
            [hashtable]$GrantControls = $null,
            [hashtable]$Locations = $null, # e.g., @{ IncludeLocations = @('All'); ExcludeLocations = @() }
            [array]$SignInRiskLevels = $null, # e.g., @('high', 'medium')
            [array]$UserRiskLevels = $null
        )
        return [pscustomobject]@{
            DisplayName      = $DisplayName
            Id               = (New-Guid).Guid
            State            = $State
            CreatedDateTime  = (Get-Date).AddDays(-10)
            ModifiedDateTime = (Get-Date).AddDays(-1)
            Conditions       = [pscustomobject]@{
                Users                = [pscustomobject]@{ IncludeUsers = @('All'); ExcludeUsers = @() } # Default, can be overridden
                Applications         = [pscustomobject]@{ IncludeApplications = @('All'); ExcludeApplications = @() } # Default
                Locations            = $Locations # Pass as hashtable
                SignInRiskLevels     = $SignInRiskLevels
                UserRiskLevels       = $UserRiskLevels
                ClientAppTypes       = @("all") # Default
                Devices              = $null # Can be expanded
            }
            GrantControls    = $GrantControls # Pass as hashtable e.g. @{ Operator = 'OR'; BuiltInControls = @('mfa') }
            SessionControls  = $null # Can be expanded
        }
    }
}

AfterAll {
    # Clean up any script-scoped variables if necessary
    Remove-Variable -Name "ExportCsv*" -Scope script -ErrorAction SilentlyContinue
    Remove-Variable -Name "NewMockPolicy" -Scope script -ErrorAction SilentlyContinue
}

Describe 'ComplianceManager Class' {
    $mockTenantId = "mock-tenant-id"
    $manager = $null # To hold ComplianceManager instance

    BeforeEach {
        # Reset mocks or script variables if they are modified within tests
        $script:ExportCsvInputObject = $null
        $script:ExportCsvPath = $null
        $script:ExportCsvNoTypeInfo = $null
        Mock Get-MgIdentityConditionalAccessPolicy { return @() } -ModuleName * # Reset to default
    }

    Context 'Constructor' {
        It 'Initializes with default frameworks if no custom ones are provided' {
            $manager = [ComplianceManager]::new($mockTenantId, $null)
            $manager.ComplianceFrameworks.Should().Not().BeNullOrEmpty()
            $manager.ComplianceFrameworks.ContainsKey('ISO27001').Should().BeTrue()
            $manager.ComplianceFrameworks['ISO27001'].ContainsKey('A.9.4.1').Should().BeTrue()
        }

        It 'Initializes with custom frameworks, overriding defaults and adding new ones' {
            $customFrameworks = @{
                'ISO27001' = @{ # Override default ISO27001
                    'CUSTOM_CONTROL_1' = @{
                        Description = "Custom Control for ISO"
                        Requirements = @("Custom Requirement A")
                    }
                }
                'MY_CUSTOM_FRAMEWORK' = @{
                    'MCF_CONTROL_1' = @{
                        Description = "My Custom Framework Control 1"
                        Requirements = @("MCF Requirement X")
                    }
                }
            }
            $manager = [ComplianceManager]::new($mockTenantId, $customFrameworks)
            $manager.ComplianceFrameworks.ContainsKey('ISO27001').Should().BeTrue()
            $manager.ComplianceFrameworks['ISO27001'].ContainsKey('A.9.4.1').Should().BeFalse("Default A.9.4.1 should be overridden")
            $manager.ComplianceFrameworks['ISO27001'].ContainsKey('CUSTOM_CONTROL_1').Should().BeTrue()
            $manager.ComplianceFrameworks.ContainsKey('MY_CUSTOM_FRAMEWORK').Should().BeTrue()
            $manager.ComplianceFrameworks['MY_CUSTOM_FRAMEWORK'].ContainsKey('MCF_CONTROL_1').Should().BeTrue()
        }
    }

    Context 'CheckRequirement Method' {
        BeforeEach {
            $manager = [ComplianceManager]::new($mockTenantId, $null) # Use default frameworks
        }

        It 'Identifies MFA enforcement correctly (policy enabled)' {
            $mfaPolicy = $script:NewMockPolicy -GrantControls @{ Operator = 'OR'; BuiltInControls = @('mfa') } -State 'enabled'
            $manager.CheckRequirement("MFA enforcement", @($mfaPolicy)).Should().BeTrue()
        }

        It 'Does not identify MFA enforcement if policy is disabled' {
            $mfaPolicy = $script:NewMockPolicy -GrantControls @{ Operator = 'OR'; BuiltInControls = @('mfa') } -State 'disabled'
            $manager.CheckRequirement("MFA enforcement", @($mfaPolicy)).Should().BeFalse()
        }

        It 'Identifies MFA enforcement correctly (no policy)' {
             $noMfaPolicy = $script:NewMockPolicy -GrantControls @{ Operator = 'OR'; BuiltInControls = @('compliantDevice') } -State 'enabled'
            $manager.CheckRequirement("MFA enforcement", @($noMfaPolicy)).Should().BeFalse()
        }

        It 'Identifies Device compliance correctly' {
            $compliantPolicy = $script:NewMockPolicy -GrantControls @{ Operator = 'OR'; BuiltInControls = @('compliantDevice') }
            $manager.CheckRequirement("Device compliance", @($compliantPolicy)).Should().BeTrue()
        }

        It 'Identifies Location-based access correctly (include specific)' {
             $locationPolicy = $script:NewMockPolicy -Locations @{ IncludeLocations = @('12345'); ExcludeLocations = @() }
            $manager.CheckRequirement("Location-based access", @($locationPolicy)).Should().BeTrue()
        }

        It 'Identifies Location-based access correctly (exclude specific)' {
             $locationPolicy = $script:NewMockPolicy -Locations @{ IncludeLocations = @('All'); ExcludeLocations = @('12345') }
            $manager.CheckRequirement("Location-based access", @($locationPolicy)).Should().BeTrue()
        }

        It 'Does not identify Location-based access for Include "All" only' {
             $locationPolicy = $script:NewMockPolicy -Locations @{ IncludeLocations = @('All'); ExcludeLocations = @() }
            $manager.CheckRequirement("Location-based access", @($locationPolicy)).Should().BeFalse()
        }

        It 'Identifies Risk-based authentication correctly (sign-in risk)' {
            $riskPolicy = $script:NewMockPolicy -SignInRiskLevels @('high', 'medium')
            $manager.CheckRequirement("Risk-based authentication", @($riskPolicy)).Should().BeTrue()
        }

         It 'Does not identify Risk-based auth if SignInRiskLevels is empty or only "none"' {
            $riskPolicyNoRisk = $script:NewMockPolicy -SignInRiskLevels @()
            $manager.CheckRequirement("Risk-based authentication", @($riskPolicyNoRisk)).Should().BeFalse()
            $riskPolicyNone = $script:NewMockPolicy -SignInRiskLevels @('none')
            $manager.CheckRequirement("Risk-based authentication", @($riskPolicyNone)).Should().BeFalse()
        }

        It 'Handles "Just-in-time access" with a warning and returns false' {
            $warningCalled = $false
            Mock Write-Warning -MockWith { $warningCalled = $true; $Message | Should -Be "Checking for 'Just-in-time access' is not fully supported by inspecting CA policies alone. This typically involves Azure AD PIM integration." }
            $manager.CheckRequirement("Just-in-time access", @($script:NewMockPolicy)).Should().BeFalse()
            $warningCalled.Should().BeTrue()
        }

        It 'Handles "Conditional access policies" requirement (policies exist)' {
            $manager.CheckRequirement("Conditional access policies", @($script:NewMockPolicy)).Should().BeTrue()
        }

        It 'Handles "Conditional access policies" requirement (no policies exist)' {
            $manager.CheckRequirement("Conditional access policies", @()).Should().BeFalse()
        }

        It 'Handles unknown requirements with a warning and returns false' {
            $warningCalled = $false
            Mock Write-Warning -MockWith { $warningCalled = $true; $Message | Should -Be "Requirement 'MY_UNKNOWN_REQUIREMENT' is unknown or not specifically checked by the enhanced logic. Defaulting to false." }
            $manager.CheckRequirement("MY_UNKNOWN_REQUIREMENT", @($script:NewMockPolicy)).Should().BeFalse()
            $warningCalled.Should().BeTrue()
        }
    }

    Context 'CalculateOverallScore Method' {
        BeforeEach {
            $manager = [ComplianceManager]::new($mockTenantId, $null)
        }

        It 'Calculates 100% for all controls compliant' {
            $controls = @{ C1 = @{ Compliant = $true }; C2 = @{ Compliant = $true } }
            $manager.CalculateOverallScore($controls).Should().Be(100.0)
        }

        It 'Calculates 0% for no controls compliant' {
            $controls = @{ C1 = @{ Compliant = $false }; C2 = @{ Compliant = $false } }
            $manager.CalculateOverallScore($controls).Should().Be(0.0)
        }

        It 'Calculates 50% for half controls compliant' {
            $controls = @{ C1 = @{ Compliant = $true }; C2 = @{ Compliant = $false } }
            $manager.CalculateOverallScore($controls).Should().Be(50.0)
        }

        It 'Calculates 66.67% for two of three controls compliant (approx)' {
            $controls = @{ C1 = @{ Compliant = $true }; C2 = @{ Compliant = $true }; C3 = @{ Compliant = $false } }
            $manager.CalculateOverallScore($controls).Should().BeApproximately(66.67, 0.01)
        }

        It 'Handles empty input gracefully (returns 0.0)' {
            $manager.CalculateOverallScore(@{}).Should().Be(0.0)
            $manager.CalculateOverallScore($null).Should().Be(0.0)
        }
    }

    Context 'AssessCompliance Method' {
        $testFrameworkName = 'TEST_FW'
        $testFramework = @{
            ($testFrameworkName) = @{
                'TFW_CTRL_1' = @{ Description = "Test Control 1"; Requirements = @("MFA enforcement") }
                'TFW_CTRL_2' = @{ Description = "Test Control 2"; Requirements = @("Device compliance", "Unknown requirement") }
            }
        }

        BeforeEach {
            $manager = [ComplianceManager]::new($mockTenantId, $testFramework)
            # Mock CheckRequirement behavior for this context if needed, or rely on its own tests
            # For AssessCompliance, we primarily test its orchestration logic
        }

        It 'Returns a correctly structured report' {
            Mock Get-MgIdentityConditionalAccessPolicy { return @() } # No policies satisfy anything
            $report = $manager.AssessCompliance($testFrameworkName)

            $report.Should().Not().BeNull()
            $report.PSObject.Properties.Name.Should().Contain(@('Framework', 'AssessmentDate', 'Controls', 'OverallScore', 'Gaps'))
            $report.Framework.Should().Be($testFrameworkName)
            $report.AssessmentDate.Should().BeOfType([datetime])
            $report.Controls.Should().Not().BeNull()
            $report.OverallScore.Should().BeOfType([double])
            $report.Gaps.Should().BeOfType([array])
        }

        It 'Assesses controls correctly (all compliant)' {
            # Mock policies that satisfy all requirements for TFW_CTRL_1 and TFW_CTRL_2's "Device compliance"
            $policyMFA = $script:NewMockPolicy -GrantControls @{ Operator = 'OR'; BuiltInControls = @('mfa') }
            $policyDevice = $script:NewMockPolicy -GrantControls @{ Operator = 'OR'; BuiltInControls = @('compliantDevice') }
            Mock Get-MgIdentityConditionalAccessPolicy { return @($policyMFA, $policyDevice) }

            # Mock Write-Warning for "Unknown requirement" to avoid noise if not testing that specifically here
            Mock Write-Warning {}

            $report = $manager.AssessCompliance($testFrameworkName)

            $report.Controls['TFW_CTRL_1'].Compliant.Should().BeTrue()
            $report.Controls['TFW_CTRL_1'].Evidence.Should().Contain("Requirement 'MFA enforcement' satisfied by policy")

            # TFW_CTRL_2 will be false because "Unknown requirement" is not met
            $report.Controls['TFW_CTRL_2'].Compliant.Should().BeFalse()
            $report.Controls['TFW_CTRL_2'].Evidence.Should().Contain("Requirement 'Device compliance' satisfied by policy")
            $report.Controls['TFW_CTRL_2'].Remediation.Should().Contain("Implement Unknown requirement")

            $report.Gaps.Count.Should().Be(1) # Only TFW_CTRL_2 due to unknown req
            $report.Gaps[0].Control.Should().Be('TFW_CTRL_2')

            # Overall score: TFW_CTRL_1 is true, TFW_CTRL_2 is false. So 1/2 = 50%
            $report.OverallScore.Should().Be(50.0)
        }

        It 'Populates Gaps correctly for non-compliant controls' {
            Mock Get-MgIdentityConditionalAccessPolicy { return @() } # No policies = nothing satisfied
            Mock Write-Warning {} # Suppress unknown req warning for this test focus

            $report = $manager.AssessCompliance($testFrameworkName)

            $report.Controls['TFW_CTRL_1'].Compliant.Should().BeFalse()
            $report.Controls['TFW_CTRL_1'].Remediation.Should().Contain("Implement MFA enforcement")

            $report.Controls['TFW_CTRL_2'].Compliant.Should().BeFalse()
            $report.Controls['TFW_CTRL_2'].Remediation.Should().Contain("Implement Device compliance")
            $report.Controls['TFW_CTRL_2'].Remediation.Should().Contain("Implement Unknown requirement")

            $report.Gaps.Count.Should().Be(2)
            ($report.Gaps.Control).Should().BeEquivalentTo(@('TFW_CTRL_1', 'TFW_CTRL_2'))
            $report.OverallScore.Should().Be(0.0)
        }
    }

    Context 'GenerateComplianceReport Method' {
        $testFrameworkName = 'CSV_TEST_FW'
        $outputCsvPath = "test_compliance_report.csv"

        # Predefined report structure to be returned by mocked AssessCompliance
        $mockReportData = @{
            Framework = $testFrameworkName
            AssessmentDate = (Get-Date -Date "2023-10-26T10:00:00Z")
            Controls = @{
                'CTRL_A' = @{ Compliant = $true; Evidence = @("Evid A1"); Remediation = @() }
                'CTRL_B' = @{ Compliant = $false; Evidence = @(); Remediation = @("Rem B1", "Rem B2") }
            }
            OverallScore = 50.0
            Gaps = @( @{ Control = 'CTRL_B'; Description = 'Control B Desc'; Remediation = 'Rem B1; Rem B2'} ) # Gaps not directly used by CSV generation per current logic
        }

        # Mocked framework definition for ControlDescription
         $mockFrameworkDef = @{
            ($testFrameworkName) = @{
                'CTRL_A' = @{ Description = "Control A Description"; Requirements = @("Req A") }
                'CTRL_B' = @{ Description = "Control B Description"; Requirements = @("Req B1", "Req B2") }
            }
        }

        BeforeEach {
            $manager = [ComplianceManager]::new($mockTenantId, $mockFrameworkDef)
            # Mock AssessCompliance to return our predefined data
            Mock ($manager.AssessCompliance) { return $mockReportData } # Mocking the instance method
        }

        It 'Exports data with correct properties to Export-Csv' {
            $manager.GenerateComplianceReport($testFrameworkName, $outputCsvPath)

            $script:ExportCsvInputObject.Should().Not().BeNullOrEmpty()
            $script:ExportCsvInputObject.Count.Should().Be(2) # Two controls in mockReportData

            $firstRow = $script:ExportCsvInputObject[0]
            $firstRow.PSObject.Properties.Name.Should().BeEquivalentTo(@(
                'Framework', 'AssessmentDate', 'OverallScore', 'ControlID',
                'ControlDescription', 'Compliant', 'Evidence', 'RemediationSteps'
            ))

            $firstRow.Framework.Should().Be($testFrameworkName)
            $firstRow.AssessmentDate.Should().Be($mockReportData.AssessmentDate.ToString("yyyy-MM-dd HH:mm:ss"))
            $firstRow.OverallScore.Should().Be($mockReportData.OverallScore)
            $firstRow.ControlID.Should().Be('CTRL_A')
            $firstRow.ControlDescription.Should().Be("Control A Description")
            $firstRow.Compliant.Should().BeTrue()
            $firstRow.Evidence.Should().Be("Evid A1")
            $firstRow.RemediationSteps.Should().Be("")

            $secondRow = $script:ExportCsvInputObject[1]
            $secondRow.ControlID.Should().Be('CTRL_B')
            $secondRow.ControlDescription.Should().Be("Control B Description")
            $secondRow.Compliant.Should().BeFalse()
            $secondRow.Evidence.Should().Be("")
            $secondRow.RemediationSteps.Should().Be("Rem B1; Rem B2")
        }

        It 'Calls Export-Csv with the correct path and NoTypeInformation' {
            $manager.GenerateComplianceReport($testFrameworkName, $outputCsvPath)
            $script:ExportCsvPath.Should().Be($outputCsvPath)
            $script:ExportCsvNoTypeInfo.Should().BeTrue()
        }

        It 'Handles empty controls data gracefully' {
            $emptyReportData = $mockReportData.Clone()
            $emptyReportData.Controls = @{}
            Mock ($manager.AssessCompliance) { return $emptyReportData }

            $manager.GenerateComplianceReport($testFrameworkName, $outputCsvPath)
            # Expect Export-Csv not to be called, or called with empty input
            # The method itself has Write-Warning "No data to write..."
            # We can check if Export-Csv was called with non-empty data
            ($null -eq $script:ExportCsvInputObject -or $script:ExportCsvInputObject.Count -eq 0).Should().BeTrue()
        }
    }
}
