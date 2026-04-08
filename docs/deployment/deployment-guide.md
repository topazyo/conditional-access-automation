# Conditional Access Policy Deployment Guide

## Prerequisites
- Azure AD / Entra tenant with appropriate licenses (e.g., Azure AD Premium P1/P2 depending on features)
- PowerShell 7.2 or higher
- Required PowerShell modules:
  - Microsoft.Graph

## Environment Setup

### 1. Authentication
This repo does not include an automated service principal creation script. Configure a service principal or use interactive login before running deployments. Example (manual steps):

```powershell
# Login interactively
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# OR use a service principal with CLIENT_ID/CLIENT_SECRET and TENANT_ID
```

TODO: add `scripts/setup` helpers to create service principals and monitoring resources.

### 2. Policy Staging Process

The repository provides a single deployment script: `scripts/deployment/deploy.ps1`. Use it with the `-ConfigPath` parameter to point to a template under `templates/deployment/`.

#### Development / Staging / Production (example)

```powershell
# Deploy using the single deploy.ps1 script and a YAML template
./scripts/deployment/deploy.ps1 `
    -TenantId <TENANT_ID> `
    -Environment Development `
    -ConfigPath ./templates/deployment/ca-policies.yaml `
    -WhatIf
```

Pass `-WhatIf` for a dry-run where supported. The script reads your YAML and uses the policy manager module to create/update policies.

### 3. Monitoring Setup
Monitoring configuration is partly implemented in `src/modules/reporting/policy_monitor.ps1`. `PolicyMonitor.ConfigureLogAnalytics` is a placeholder and there are no `scripts/setup/configure-monitoring.ps1` helper scripts in the repository.

TODO: implement `scripts/setup/configure-monitoring.ps1` or document manual Log Analytics setup steps.

## Rollback / Maintenance

There is a maintenance script available: `scripts/maintenance/policy-cleanup.ps1`. The repo does not contain a `rollback-policies.ps1` script; use `policy-cleanup.ps1` or the `ConditionalAccessPolicyManager` class methods to revert changes.

Example: run maintenance cleanup interactively

```powershell
./scripts/maintenance/policy-cleanup.ps1 -WhatIf
```

TODO: add a documented emergency rollback procedure that uses `ConditionalAccessPolicyManager.RemovePolicy` or provide a scripted helper.