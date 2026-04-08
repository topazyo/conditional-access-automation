# Conditional Access Incident Response Playbook

This playbook contains guidance for common Conditional Access incidents and points to repository maintenance scripts where available.

## High-Priority Incidents

### 1. VIP Access Blocked

There is no `grant-emergency-access.ps1` script in the repository. Use `ConditionalAccessPolicyManager` to create a temporary exclusion or modify the policy interactively.

Example (interactive):

```powershell
Import-Module ./src/modules/policy-management/policy_manager.ps1
$mgr = [ConditionalAccessPolicyManager]::new('<tenant-id>')
# Use $mgr methods to apply a temporary exclusion (see source for exact API)
```

TODO: add maintenance helper script `scripts/maintenance/grant-emergency-access.ps1` for common emergency workflows.

### 2. Mass Sign-In Failures

The repository does not include `scripts/operations/analyze-signin-failures.ps1`. Use your SigninLogs in Log Analytics or Azure Monitor to analyze failures and then use `scripts/maintenance/policy-cleanup.ps1` or the policy manager class to apply mitigations.

Example KQL and mitigation workflow:

```kusto
// High failure rate detection
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailureCount=count() by PolicyName=ConditionalAccessPolicies
| where FailureCount > 100
```

Mitigation example (interactive):

```powershell
# Inspect policy and decide on mitigation
Import-Module ./scripts/maintenance/policy-cleanup.ps1
./scripts/maintenance/policy-cleanup.ps1 -WhatIf
```

TODO: provide `scripts/operations/analyze-signin-failures.ps1` and scripted mitigation helpers.