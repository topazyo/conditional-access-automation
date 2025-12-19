# Conditional Access Incident Response Playbook

## High-Priority Incidents

### 1. VIP Access Blocked
```powershell
# Quick VIP access resolution
$vipConfig = @{
    UserPrincipalName = "executive@company.com"
    TemporaryExclusion = $true
    Duration = "2hours"
    Reason = "Emergency access required for board meeting"
}

./scripts/maintenance/grant-emergency-access.ps1 @vipConfig
```

### 2. Mass Sign-In Failures
```powershell
# Identify impacted policies
$impactAnalysis = ./scripts/operations/analyze-signin-failures.ps1 `
    -TimeWindow "1hour" `
    -ThresholdPercentage 20

# Apply temporary mitigation
if ($impactAnalysis.RequiresAction) {
    ./scripts/maintenance/apply-emergency-exclusion.ps1 `
        -PolicyId $impactAnalysis.ProblemPolicy `
        -Duration "1hour"
}
```

## Monitoring and Alerting

### KQL Queries for Common Scenarios
```kusto
// High failure rate detection
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailureCount=count() by PolicyName=ConditionalAccessPolicies
| where FailureCount > 100

// Suspicious policy modifications
AuditLogs
| where OperationType == "Update"
| where Category == "Policy"
| project TimeGenerated, Actor=InitiatedBy.user.userPrincipalName, 
    PolicyName=TargetResources[0].displayName
```