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
(Note: The script `grant-emergency-access.ps1` is a conceptual placeholder for future enhancement. Emergency access typically involves pre-defined break-glass accounts or manual exclusion from policies via the Azure portal by authorized administrators.)

### 2. Mass Sign-In Failures
```powershell
# Identify impacted policies
$impactAnalysis = ./scripts/operations/analyze-signin-failures.ps1 `
    -TimeWindow "1hour" `
    -ThresholdPercentage 20
(Note: The script `analyze-signin-failures.ps1` is a conceptual placeholder. Analysis of sign-in failures should be performed using Azure AD Sign-in logs, Azure Monitor Workbooks, or Log Analytics queries as shown below.)

# Apply temporary mitigation
if ($impactAnalysis.RequiresAction) {
    ./scripts/maintenance/apply-emergency-exclusion.ps1 `
        -PolicyId $impactAnalysis.ProblemPolicy `
        -Duration "1hour"
}
```
(Note: The script `apply-emergency-exclusion.ps1` is a conceptual placeholder. Applying emergency exclusions usually involves manually disabling a problematic policy or adding specific user/group exclusions via the Azure portal or targeted Graph API calls under strict change control.)

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