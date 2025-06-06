class PolicyMonitor {
    [string]$WorkspaceId
    [string]$LogAnalyticsKey
    hidden [object]$GraphConnection

    PolicyMonitor([string]$workspaceId, [string]$logAnalyticsKey) {
        $this.WorkspaceId = $workspaceId
        $this.LogAnalyticsKey = $logAnalyticsKey
        $this.ConnectToServices()
    }

    hidden [void]ConnectToServices() {
        try {
            $this.GraphConnection = Connect-MgGraph -Scopes "Policy.Read.All", "AuditLog.Read.All"
            
            # Set up Log Analytics connection
            $this.ConfigureLogAnalytics()
        }
        catch {
            throw "Failed to connect to monitoring services: $_"
        }
    }

    # Configures and validates Log Analytics connection parameters.
    hidden [void]ConfigureLogAnalytics() {
        if ([string]::IsNullOrEmpty($this.WorkspaceId) -or [string]::IsNullOrEmpty($this.LogAnalyticsKey)) {
            Write-Warning "Log Analytics Workspace ID or Primary Key is missing or empty. Log Analytics integration will be disabled."
            # Optionally, set a flag to prevent attempts to send data
            # $this.LogAnalyticsEnabled = $false
            return
        }

        # If parameters are present, indicate readiness.
        # A more advanced check could involve a test API call if available and safe,
        # but for now, presence of parameters is the main check.
        Write-Verbose "Log Analytics Workspace ID and Key are present. Ready to send data to Log Analytics."
        # $this.LogAnalyticsEnabled = $true
    }

    [hashtable]GenerateMetricsReport([datetime]$startDate, [datetime]$endDate) {
        Write-Verbose "Generating metrics report from $($startDate.ToString('o')) to $($endDate.ToString('o'))"
        $report = @{
            TimeRange = @{
                Start = $startDate
                End = $endDate
            }
            PolicyMetrics = @{
                TotalPolicies = 0
                ActivePolicies = 0
                FailedSignIns = 0       # Sign-ins where Status.ErrorCode -ne 0
                SuccessfulSignIns = 0   # Sign-ins where Status.ErrorCode -eq 0
                MFAChallenges = 0       # Sign-ins where MFA was enforced by CA
            }
            UserImpact = @{
                TotalUsers = 0          # Unique users from sign-in logs
                BlockedUsers = 0        # Unique users blocked by CA
                # MFAPrompts removed as per requirement
            }
            Recommendations = @()
        }

        # 1. Calculate TotalPolicies and ActivePolicies
        try {
            Write-Verbose "Fetching all Conditional Access policies..."
            $allPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
            $report.PolicyMetrics.TotalPolicies = $allPolicies.Count
            $report.PolicyMetrics.ActivePolicies = ($allPolicies | Where-Object {$_.State -eq 'enabled'}).Count
            Write-Verbose "Found $($report.PolicyMetrics.TotalPolicies) total policies, $($report.PolicyMetrics.ActivePolicies) active policies."
        }
        catch {
            Write-Error "Failed to retrieve Conditional Access policies: $($_.Exception.Message)"
            # Decide if to throw or continue with partial data
        }

        # 2. Get and Process Sign-in Logs
        $uniqueUsers = [System.Collections.Generic.HashSet[string]]::new()
        $blockedUserSet = [System.Collections.Generic.HashSet[string]]::new()
        
        # Corrected date format for Graph API filter
        $filterString = "createdDateTime ge $($startDate.ToUniversalTime().ToString("o")) and createdDateTime le $($endDate.ToUniversalTime().ToString("o"))"
        Write-Verbose "Using sign-in log filter: $filterString"

        try {
            $signInLogs = Get-MgAuditLogSignIn -Filter $filterString -All -ErrorAction Stop
            Write-Verbose "Retrieved $($signInLogs.Count) sign-in log entries."

            foreach ($log in $signInLogs) {
                # Add user to unique users set
                if (-not [string]::IsNullOrEmpty($log.UserPrincipalName)) {
                    $uniqueUsers.Add($log.UserPrincipalName) | Out-Null
                }

                # Increment SuccessfulSignIns or FailedSignIns
                if ($log.Status.ErrorCode -eq 0) {
                    $report.PolicyMetrics.SuccessfulSignIns++
                } else {
                    $report.PolicyMetrics.FailedSignIns++
                    # Check if Conditional Access was the cause of failure
                    if ($log.ConditionalAccessStatus -eq 'failure') {
                        if (-not [string]::IsNullOrEmpty($log.UserPrincipalName)) {
                            $blockedUserSet.Add($log.UserPrincipalName) | Out-Null
                        }
                    }
                }

                # Refine MFAChallenges: Check if any applied CA policy enforced MFA
                if ($null -ne $log.AppliedConditionalAccessPolicies) {
                    foreach ($appliedPolicy in $log.AppliedConditionalAccessPolicies) {
                        if ($null -ne $appliedPolicy.EnforcedGrantControls -and ($appliedPolicy.EnforcedGrantControls -contains 'mfa' -or $appliedPolicy.EnforcedGrantControls -contains 'multiFactorAuthentication')) {
                            $report.PolicyMetrics.MFAChallenges++
                            break # Count MFA challenge once per sign-in log, even if multiple policies enforced it
                        }
                    }
                }
            }

            $report.UserImpact.TotalUsers = $uniqueUsers.Count
            $report.UserImpact.BlockedUsers = $blockedUserSet.Count
            Write-Verbose "Processed sign-in logs: $($report.UserImpact.TotalUsers) unique users, $($report.UserImpact.BlockedUsers) users blocked by CA."

        }
        catch {
            Write-Error "Failed to retrieve or process sign-in logs: $($_.Exception.Message)"
            # Decide if to throw or continue with partial data
        }

        # Generate recommendations based on the (potentially partially) populated metrics
        # Ensure metrics used by GenerateRecommendations are initialized to avoid division by zero if logs failed
        if (($report.PolicyMetrics.SuccessfulSignIns + $report.PolicyMetrics.FailedSignIns) -gt 0) { # Check if any sign-ins processed
            $report.Recommendations = $this.GenerateRecommendations($report.PolicyMetrics)
        } else {
             Write-Warning "No sign-in logs processed, skipping recommendations generation."
        }

        return $report
    }

    [void]MonitorPolicyChanges() {
        $filter = "resourceType eq 'conditionalAccessPolicy'"
        $auditLogs = Get-MgAuditLogDirectoryAudit -Filter $filter

        foreach ($log in $auditLogs) {
            $this.LogPolicyChange($log)
        }
    }

    hidden [void]LogPolicyChange($change) {
        # Prepare a structured representation of ModifiedProperties
        $structuredChanges = @()
        if ($null -ne $change.TargetResources.ModifiedProperties) {
            foreach ($prop in $change.TargetResources.ModifiedProperties) {
                $structuredChanges += @{
                    DisplayName = $prop.DisplayName
                    NewValue    = $prop.NewValue # These are likely already JSON strings or simple types
                    OldValue    = $prop.OldValue # These are likely already JSON strings or simple types
                }
            }
        }

        $logEntry = @{
            TimeGenerated = Get-Date # Consider using $change.ActivityDateTime for more accurate event time
            ActivityDateTime = $change.ActivityDateTime # Include the original audit log event time
            ChangeType    = $change.OperationType
            PolicyId      = $change.TargetResources.Id
            PolicyName    = $change.TargetResources.DisplayName # Include policy name if available
            ModifiedBy    = $change.InitiatedBy.User.UserPrincipalName
            AppModifiedBy = $change.InitiatedBy.App.DisplayName # If modified by an App/SPN
            Changes       = $structuredChanges # Assign the array of hashtables
        }

        # Send to Log Analytics
        $this.SendToLogAnalytics("PolicyChanges", $logEntry)
    }

    hidden [void]SendToLogAnalytics([string]$logType, [hashtable]$logEntry) {
        # Ensure WorkspaceId and LogAnalyticsKey are present
        if ([string]::IsNullOrEmpty($this.WorkspaceId) -or [string]::IsNullOrEmpty($this.LogAnalyticsKey)) {
            Write-Warning "Log Analytics Workspace ID or Key is not configured. Skipping sending log for '$logType'."
            return
        }

        # The $logEntry already contains Changes as an array of hashtables.
        # ConvertTo-Json will now serialize this structure correctly.
        # Using a depth of 5, adjust if necessary for deeper structures, though ModifiedPropertyObject is fairly flat.
        $jsonBody = $logEntry | ConvertTo-Json -Depth 5 -Compress

        $headers = @{
            "Authorization" = "SharedKey $($this.WorkspaceId):$($this.LogAnalyticsKey)"
            "Log-Type" = $logType
            "x-ms-date" = [DateTime]::UtcNow.ToString("r")
        }

        $uri = "https://$($this.WorkspaceId).ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

        try {
            Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $jsonBody -ContentType "application/json"
        }
        catch {
            Write-Error "Failed to send logs to Log Analytics: $_"
        }
    }

    hidden [array]GenerateRecommendations([hashtable]$metrics) {
        $recommendations = @()

        # Analyze failed sign-ins
        if ($metrics.FailedSignIns / ($metrics.SuccessfulSignIns + $metrics.FailedSignIns) -gt 0.1) {
            $recommendations += "High failure rate detected. Review policy conditions for potential conflicts."
        }

        # Analyze MFA usage
        if ($metrics.MFAChallenges / $metrics.SuccessfulSignIns -lt 0.5) {
            $recommendations += "Low MFA adoption rate. Consider expanding MFA requirements."
        }

        return $recommendations
    }
}